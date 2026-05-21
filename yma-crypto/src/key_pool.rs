use std::collections::HashMap;

pub struct KeyPool {
    pools: HashMap<String, Vec<KeyEntry>>,
    default_max_keys: usize,
}

pub struct KeyEntry {
    pub key_id: String,
    pub key_bytes: Vec<u8>,
    pub algorithm: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub usage_count: u64,
    pub is_active: bool,
    pub metadata: HashMap<String, String>,
}

impl KeyPool {
    pub fn new(default_max_keys: usize) -> Self {
        Self {
            pools: HashMap::new(),
            default_max_keys,
        }
    }

    pub fn create_pool(&mut self, pool_name: &str, max_keys: Option<usize>) -> &mut Vec<KeyEntry> {
        self.pools.entry(pool_name.to_string()).or_insert_with(|| Vec::with_capacity(max_keys.unwrap_or(self.default_max_keys)))
    }

    pub fn add_key(&mut self, pool_name: &str, key_id: String, key_bytes: Vec<u8>, algorithm: String, expires_at: Option<u64>) -> Result<(), String> {
        let pool = self.pools.get_mut(pool_name).ok_or_else(|| format!("pool not found: {}", pool_name))?;
        if pool.iter().any(|k| k.key_id == key_id) {
            return Err(format!("key_id already exists: {}", key_id));
        }
        let max = self.default_max_keys;
        if pool.len() >= max {
            return Err(format!("pool '{}' has reached max capacity of {}", pool_name, max));
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        pool.push(KeyEntry {
            key_id,
            key_bytes,
            algorithm,
            created_at: now,
            expires_at,
            usage_count: 0,
            is_active: true,
            metadata: HashMap::new(),
        });
        Ok(())
    }

    pub fn get_key(&mut self, pool_name: &str, key_id: &str) -> Option<&mut KeyEntry> {
        let pool = self.pools.get_mut(pool_name)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let entry = pool.iter_mut().find(|k| k.key_id == key_id && k.is_active)?;
        if let Some(exp) = entry.expires_at {
            if now > exp {
                entry.is_active = false;
                return None;
            }
        }
        entry.usage_count += 1;
        Some(entry)
    }

    pub fn get_key_readonly(&self, pool_name: &str, key_id: &str) -> Option<&KeyEntry> {
        let pool = self.pools.get(pool_name)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let entry = pool.iter().find(|k| k.key_id == key_id && k.is_active)?;
        if let Some(exp) = entry.expires_at {
            if now > exp { return None; }
        }
        Some(entry)
    }

    pub fn remove_key(&mut self, pool_name: &str, key_id: &str) -> bool {
        if let Some(pool) = self.pools.get_mut(pool_name) {
            let before = pool.len();
            pool.retain(|k| k.key_id != key_id);
            pool.len() < before
        } else {
            false
        }
    }

    pub fn deactivate_key(&mut self, pool_name: &str, key_id: &str) -> bool {
        if let Some(pool) = self.pools.get_mut(pool_name) {
            if let Some(entry) = pool.iter_mut().find(|k| k.key_id == key_id) {
                entry.is_active = false;
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn list_keys(&self, pool_name: &str) -> Vec<&KeyEntry> {
        self.pools.get(pool_name).map(|p| p.iter().filter(|k| k.is_active).collect()).unwrap_or_default()
    }

    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }

    pub fn total_key_count(&self) -> usize {
        self.pools.values().map(|p| p.iter().filter(|k| k.is_active).count()).sum()
    }

    pub fn cleanup_expired(&mut self, pool_name: &str) -> usize {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        if let Some(pool) = self.pools.get_mut(pool_name) {
            let before = pool.len();
            pool.retain(|k| {
                if let Some(exp) = k.expires_at {
                    now <= exp
                } else {
                    true
                }
            });
            before - pool.len()
        } else {
            0
        }
    }

    pub fn get_stats(&self) -> KeyPoolStats {
        let total_active: usize = self.pools.values()
            .flat_map(|p| p.iter())
            .filter(|k| k.is_active)
            .count();
        let total_usage: u64 = self.pools.values()
            .flat_map(|p| p.iter())
            .map(|k| k.usage_count)
            .sum();
        KeyPoolStats {
            pool_count: self.pools.len(),
            total_active_keys: total_active,
            total_usage_count: total_usage,
        }
    }
}

pub struct KeyPoolStats {
    pub pool_count: usize,
    pub total_active_keys: usize,
    pub total_usage_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pool() {
        let mut pool = KeyPool::new(100);
        pool.create_pool("sms", None);
        assert_eq!(pool.pool_count(), 1);
    }

    #[test]
    fn test_add_and_get_key() {
        let mut pool = KeyPool::new(100);
        pool.create_pool("test", None);
        pool.add_key("test", "key1".into(), vec![0u8; 32], "SM4".into(), None).unwrap();
        let entry = pool.get_key("test", "key1");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().usage_count, 1);
    }

    #[test]
    fn test_duplicate_key_id() {
        let mut pool = KeyPool::new(100);
        pool.create_pool("test", None);
        pool.add_key("test", "key1".into(), vec![1u8; 16], "AES".into(), None).unwrap();
        let result = pool.add_key("test", "key1".into(), vec![2u8; 16], "AES".into(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_expiry() {
        let mut pool = KeyPool::new(100);
        pool.create_pool("test", None);
        let past = 1000u64;
        pool.add_key("test", "expired".into(), vec![0u8; 16], "SM4".into(), Some(past)).unwrap();
        assert!(pool.get_key("test", "expired").is_none());
    }

    #[test]
    fn test_remove_key() {
        let mut pool = KeyPool::new(10);
        pool.create_pool("test", None);
        pool.add_key("test", "k1".into(), vec![0u8; 16], "SM4".into(), None).unwrap();
        assert!(pool.remove_key("test", "k1"));
        assert!(!pool.remove_key("test", "nonexistent"));
    }

    #[test]
    fn test_deactivate_and_reactivate() {
        let mut pool = KeyPool::new(10);
        pool.create_pool("test", None);
        pool.add_key("test", "k1".into(), vec![0u8; 16], "SM4".into(), None).unwrap();
        assert!(pool.deactivate_key("test", "k1"));
        assert!(pool.get_key("test", "k1").is_none());
    }

    #[test]
    fn test_list_keys() {
        let mut pool = KeyPool::new(100);
        pool.create_pool("test", None);
        pool.add_key("test", "a".into(), vec![0u8; 16], "SM4".into(), None).unwrap();
        pool.add_key("test", "b".into(), vec![1u8; 16], "SM4".into(), None).unwrap();
        assert_eq!(pool.list_keys("test").len(), 2);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut pool = KeyPool::new(100);
        pool.create_pool("test", None);
        pool.add_key("test", "valid".into(), vec![0u8; 16], "SM4".into(), None).unwrap();
        pool.add_key("test", "exp".into(), vec![1u8; 16], "SM4".into(), Some(1)).unwrap();
        assert_eq!(pool.cleanup_expired("test"), 1);
        assert_eq!(pool.list_keys("test").len(), 1);
    }
}