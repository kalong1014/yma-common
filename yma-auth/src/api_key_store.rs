//! yma-auth::api_key_store — API Key 存储与管理
//!
//! 提供 ApiKeyStore 存储结构，支持权限管理和启用/禁用

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::api_key::ApiKeyGenerator;

/// API Key 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub key_prefix: String,
    pub name: String,
    pub tenant_id: Uuid,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// API Key 存储
#[derive(Debug, Default)]
pub struct ApiKeyStore {
    keys: HashMap<String, ApiKeyRecord>, // key_prefix -> record
    tenant_keys: HashMap<Uuid, Vec<String>>, // tenant_id -> key_prefixes
}

impl ApiKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            tenant_keys: HashMap::new(),
        }
    }

    /// 创建新的 API Key
    pub fn create_key(
        &mut self,
        name: String,
        tenant_id: Uuid,
        permissions: Vec<String>,
        expires_days: Option<u32>,
    ) -> (String, ApiKeyRecord) {
        let (key_id, full_key) = ApiKeyGenerator::generate();
        let key_prefix = ApiKeyGenerator::extract_key_id(&full_key).unwrap_or_else(|| key_id[..8].to_string());

        let expires_at = expires_days.map(|days| Utc::now() + chrono::Duration::days(days as i64));

        let record = ApiKeyRecord {
            id: Uuid::new_v4(),
            key_prefix: key_prefix.clone(),
            name,
            tenant_id,
            permissions,
            enabled: true,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at,
        };

        self.keys.insert(key_prefix.clone(), record.clone());
        self.tenant_keys
            .entry(tenant_id)
            .or_default()
            .push(key_prefix.clone());

        (full_key, record)
    }

    /// 通过 key_prefix 查找记录
    pub fn get_by_prefix(&self, key_prefix: &str) -> Option<&ApiKeyRecord> {
        self.keys.get(key_prefix)
    }

    /// 通过完整 API Key 查找记录
    pub fn get_by_full_key(&self, full_key: &str) -> Option<&ApiKeyRecord> {
        let prefix = ApiKeyGenerator::extract_key_id(full_key)?;
        self.keys.get(&prefix)
    }

    /// 验证 API Key 是否有效
    pub fn validate_key(&self, full_key: &str) -> bool {
        if let Some(record) = self.get_by_full_key(full_key) {
            if !record.enabled {
                return false;
            }
            if let Some(expires_at) = record.expires_at {
                if Utc::now() > expires_at {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// 获取 Key 的权限列表
    pub fn get_permissions(&self, full_key: &str) -> Option<Vec<String>> {
        self.get_by_full_key(full_key)
            .map(|r| r.permissions.clone())
    }

    /// 禁用 Key
    pub fn disable_key(&mut self, key_prefix: &str) -> bool {
        if let Some(record) = self.keys.get_mut(key_prefix) {
            record.enabled = false;
            true
        } else {
            false
        }
    }

    /// 启用 Key
    pub fn enable_key(&mut self, key_prefix: &str) -> bool {
        if let Some(record) = self.keys.get_mut(key_prefix) {
            record.enabled = true;
            true
        } else {
            false
        }
    }

    /// 删除 Key
    pub fn delete_key(&mut self, key_prefix: &str) -> bool {
        if let Some(record) = self.keys.remove(key_prefix) {
            if let Some(list) = self.tenant_keys.get_mut(&record.tenant_id) {
                list.retain(|k| k != key_prefix);
            }
            true
        } else {
            false
        }
    }

    /// 更新最后使用时间
    pub fn touch_key(&mut self, key_prefix: &str) {
        if let Some(record) = self.keys.get_mut(key_prefix) {
            record.last_used_at = Some(Utc::now());
        }
    }

    /// 获取租户的所有 Key
    pub fn get_tenant_keys(&self, tenant_id: &Uuid) -> Vec<&ApiKeyRecord> {
        self.tenant_keys
            .get(tenant_id)
            .map(|prefixes| {
                prefixes
                    .iter()
                    .filter_map(|p| self.keys.get(p))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 获取所有 Key
    pub fn get_all_keys(&self) -> Vec<&ApiKeyRecord> {
        self.keys.values().collect()
    }

    /// 清理过期 Key
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .keys
            .iter()
            .filter(|(_, r)| {
                r.expires_at.map(|exp| now > exp).unwrap_or(false)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired {
            self.delete_key(key);
        }
        expired.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_key() {
        let mut store = ApiKeyStore::new();
        let (full_key, record) = store.create_key(
            "Test Key".to_string(),
            Uuid::new_v4(),
            vec!["read".to_string()],
            None,
        );

        assert!(ApiKeyGenerator::validate(&full_key));
        assert_eq!(record.name, "Test Key");
        assert!(record.enabled);
    }

    #[test]
    fn test_validate_key() {
        let mut store = ApiKeyStore::new();
        let (full_key, _) = store.create_key(
            "Test".to_string(),
            Uuid::new_v4(),
            vec!["read".to_string()],
            None,
        );

        assert!(store.validate_key(&full_key));
        assert!(!store.validate_key("invalid_key"));
    }

    #[test]
    fn test_disable_enable_key() {
        let mut store = ApiKeyStore::new();
        let (full_key, record) = store.create_key(
            "Test".to_string(),
            Uuid::new_v4(),
            vec![],
            None,
        );

        let prefix = record.key_prefix.clone();
        store.disable_key(&prefix);
        assert!(!store.validate_key(&full_key));

        store.enable_key(&prefix);
        assert!(store.validate_key(&full_key));
    }

    #[test]
    fn test_expired_key() {
        let mut store = ApiKeyStore::new();
        let (full_key, _) = store.create_key(
            "Test".to_string(),
            Uuid::new_v4(),
            vec![],
            Some(0), // 0天，立即过期
        );

        assert!(!store.validate_key(&full_key));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = ApiKeyStore::new();
        store.create_key("Expired".to_string(), Uuid::new_v4(), vec![], Some(0));
        store.create_key("Valid".to_string(), Uuid::new_v4(), vec![], Some(30));

        let cleaned = store.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(store.get_all_keys().len(), 1);
    }
}