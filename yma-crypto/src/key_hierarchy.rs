use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// 四级密钥体系管理器
pub struct KeyManager {
    master_key: Arc<RwLock<Vec<u8>>>,
    app_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    user_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    session_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            master_key: Arc::new(RwLock::new(Vec::new())),
            app_keys: Arc::new(RwLock::new(HashMap::new())),
            user_keys: Arc::new(RwLock::new(HashMap::new())),
            session_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn derive_master(&self, seed: &[u8]) -> Vec<u8> {
        use crate::sm3;
        let key = sm3::hash(seed);
        *self.master_key.write() = key.clone();
        key
    }

    pub fn derive_application(&self, app_id: &str) -> Vec<u8> {
        let master = self.master_key.read().clone();
        if master.is_empty() {
            return Vec::new();
        }
        use crate::sm3;
        let mut input = master.clone();
        input.extend_from_slice(app_id.as_bytes());
        let key = sm3::hash(&input);
        self.app_keys.write().insert(app_id.to_string(), key.clone());
        key
    }

    pub fn derive_user(&self, user_id: &str) -> Vec<u8> {
        use crate::sm3;
        let mut input = Vec::new();
        if let Some(latest_app_key) = self.app_keys.read().values().last() {
            input.extend_from_slice(latest_app_key);
        }
        input.extend_from_slice(user_id.as_bytes());
        let key = sm3::hash(&input);
        self.user_keys.write().insert(user_id.to_string(), key.clone());
        key
    }

    pub fn derive_session(&self, user_id: &str, session_id: &str) -> Vec<u8> {
        use crate::sm3;
        let user_key = self.user_keys.read().get(user_id).cloned().unwrap_or_default();
        let mut input = user_key;
        input.extend_from_slice(session_id.as_bytes());
        let key = sm3::hash(&input);
        self.session_keys.write().insert(session_id.to_string(), key.clone());
        key
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derive_hierarchy() {
        let km = KeyManager::new();
        let master = km.derive_master(b"master_seed");
        assert_eq!(master.len(), 32);

        let app_key = km.derive_application("app_001");
        assert_eq!(app_key.len(), 32);
        assert_ne!(master, app_key);

        let user_key = km.derive_user("user_123");
        assert_eq!(user_key.len(), 32);
        assert_ne!(app_key, user_key);

        let session_key = km.derive_session("user_123", "session_abc");
        assert_eq!(session_key.len(), 32);
        assert_ne!(user_key, session_key);
    }

    #[test]
    fn test_key_derive_empty_master() {
        let km = KeyManager::new();
        let app_key = km.derive_application("test");
        assert!(app_key.is_empty());
    }

    #[test]
    fn test_key_derive_different_apps() {
        let km = KeyManager::new();
        km.derive_master(b"seed");
        let key1 = km.derive_application("app1");
        let key2 = km.derive_application("app2");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_derive_consistency() {
        let km = KeyManager::new();
        km.derive_master(b"fixed_seed");
        let key1 = km.derive_application("app");
        let key2 = km.derive_application("app");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 0);
    }
}