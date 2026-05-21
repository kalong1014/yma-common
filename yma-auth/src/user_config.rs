//! yma-auth::user_config — 用户配置管理
//!
//! 提供用户级配置的存储和读取，支持键值对和结构化数据

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// 用户配置项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfigItem {
    pub key: String,
    pub value: serde_json::Value,
    pub updated_at: i64,
}

/// 用户配置存储
#[derive(Debug, Default)]
pub struct UserConfigStore {
    configs: HashMap<Uuid, HashMap<String, serde_json::Value>>,
}

impl UserConfigStore {
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
        }
    }

    /// 设置用户配置项
    pub fn set(&mut self, user_id: Uuid, key: &str, value: serde_json::Value) {
        let user_config = self.configs.entry(user_id).or_default();
        user_config.insert(key.to_string(), value);
    }

    /// 获取用户配置项
    pub fn get(&self, user_id: &Uuid, key: &str) -> Option<&serde_json::Value> {
        self.configs.get(user_id)?.get(key)
    }

    /// 获取用户所有配置
    pub fn get_all(&self, user_id: &Uuid) -> Option<&HashMap<String, serde_json::Value>> {
        self.configs.get(user_id)
    }

    /// 删除用户配置项
    pub fn delete(&mut self, user_id: &Uuid, key: &str) -> bool {
        if let Some(user_config) = self.configs.get_mut(user_id) {
            user_config.remove(key).is_some()
        } else {
            false
        }
    }

    /// 删除用户所有配置
    pub fn delete_user(&mut self, user_id: &Uuid) -> bool {
        self.configs.remove(user_id).is_some()
    }

    /// 获取布尔值配置
    pub fn get_bool(&self, user_id: &Uuid, key: &str, default: bool) -> bool {
        self.get(user_id, key)
            .and_then(|v| v.as_bool())
            .unwrap_or(default)
    }

    /// 获取字符串值配置
    pub fn get_string(&self, user_id: &Uuid, key: &str, default: &str) -> String {
        self.get(user_id, key)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    }

    /// 获取整数值配置
    pub fn get_i64(&self, user_id: &Uuid, key: &str, default: i64) -> i64 {
        self.get(user_id, key)
            .and_then(|v| v.as_i64())
            .unwrap_or(default)
    }

    /// 获取浮点值配置
    pub fn get_f64(&self, user_id: &Uuid, key: &str, default: f64) -> f64 {
        self.get(user_id, key)
            .and_then(|v| v.as_f64())
            .unwrap_or(default)
    }

    /// 检查配置项是否存在
    pub fn exists(&self, user_id: &Uuid, key: &str) -> bool {
        self.configs
            .get(user_id)
            .map(|c| c.contains_key(key))
            .unwrap_or(false)
    }

    /// 获取用户配置数量
    pub fn user_config_count(&self, user_id: &Uuid) -> usize {
        self.configs.get(user_id).map(|c| c.len()).unwrap_or(0)
    }

    /// 获取所有用户ID
    pub fn get_user_ids(&self) -> Vec<Uuid> {
        self.configs.keys().cloned().collect()
    }

    /// 批量设置配置
    pub fn set_batch(&mut self, user_id: Uuid, items: HashMap<String, serde_json::Value>) {
        let user_config = self.configs.entry(user_id).or_default();
        for (key, value) in items {
            user_config.insert(key, value);
        }
    }

    /// 导出用户配置为 JSON
    pub fn export_user_config(&self, user_id: &Uuid) -> Option<serde_json::Value> {
        self.configs.get(user_id).map(|config| {
            serde_json::to_value(config).unwrap_or(serde_json::Value::Object(Default::default()))
        })
    }

    /// 从 JSON 导入用户配置
    pub fn import_user_config(
        &mut self,
        user_id: Uuid,
        config: serde_json::Value,
    ) -> Result<(), String> {
        if let serde_json::Value::Object(map) = config {
            let user_config = self.configs.entry(user_id).or_default();
            for (key, value) in map {
                user_config.insert(key, value);
            }
            Ok(())
        } else {
            Err("Config must be a JSON object".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let mut store = UserConfigStore::new();
        let user_id = Uuid::new_v4();

        store.set(user_id, "theme", serde_json::json!("dark"));
        store.set(user_id, "notifications", serde_json::json!(true));

        assert_eq!(
            store.get(&user_id, "theme"),
            Some(&serde_json::json!("dark"))
        );
        assert_eq!(
            store.get(&user_id, "notifications"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn test_get_typed() {
        let mut store = UserConfigStore::new();
        let user_id = Uuid::new_v4();

        store.set(user_id, "enabled", serde_json::json!(true));
        store.set(user_id, "name", serde_json::json!("test"));
        store.set(user_id, "count", serde_json::json!(42));
        store.set(user_id, "rate", serde_json::json!(3.14));

        assert!(store.get_bool(&user_id, "enabled", false));
        assert_eq!(store.get_string(&user_id, "name", ""), "test");
        assert_eq!(store.get_i64(&user_id, "count", 0), 42);
        assert_eq!(store.get_f64(&user_id, "rate", 0.0), 3.14);
    }

    #[test]
    fn test_delete() {
        let mut store = UserConfigStore::new();
        let user_id = Uuid::new_v4();

        store.set(user_id, "key1", serde_json::json!("value1"));
        assert!(store.delete(&user_id, "key1"));
        assert!(!store.exists(&user_id, "key1"));
    }

    #[test]
    fn test_import_export() {
        let mut store = UserConfigStore::new();
        let user_id = Uuid::new_v4();

        let config = serde_json::json!({
            "theme": "dark",
            "language": "zh-CN"
        });

        store.import_user_config(user_id, config.clone()).unwrap();
        let exported = store.export_user_config(&user_id).unwrap();

        assert_eq!(exported["theme"], "dark");
        assert_eq!(exported["language"], "zh-CN");
    }
}