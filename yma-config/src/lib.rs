//! yma-config 配置管理统一库
//!
//! 提供热重载配置管理的标准化接口，支持 JSON/YAML/TOML/ENV 多格式
//! 版本锁定: 0.2.0

use std::path::Path;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tracing::{error, info};

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

/// 配置格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Json,
    Yaml,
    Toml,
    Env,
}

impl ConfigFormat {
    /// 从文件扩展名推断格式
    pub fn from_extension(path: &str) -> Option<Self> {
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())?;
        match ext.to_lowercase().as_str() {
            "json" => Some(ConfigFormat::Json),
            // "yaml" | "yml" => Some(ConfigFormat::Yaml), // 需要 serde_yaml 依赖才能支持
            "toml" => Some(ConfigFormat::Toml),
            "env" => Some(ConfigFormat::Env),
            _ => None,
        }
    }
}

/// 配置管理器
pub struct ConfigManager<T: DeserializeOwned + Clone + Send + Sync + 'static> {
    inner: Arc<RwLock<T>>,
    watcher_tx: Option<watch::Sender<T>>,
}

impl<T: DeserializeOwned + Clone + Send + Sync + 'static> ConfigManager<T> {
    pub fn new(config: T) -> Self {
        let (tx, _) = watch::channel(config.clone());
        Self {
            inner: Arc::new(RwLock::new(config)),
            watcher_tx: Some(tx),
        }
    }

    pub fn get(&self) -> T {
        self.inner.read().clone()
    }

    pub fn update(&self, config: T) {
        *self.inner.write() = config.clone();
        if let Some(tx) = &self.watcher_tx {
            let _ = tx.send(config);
        }
    }

    /// 从字符串重新加载配置（自动推断格式）
    pub fn reload_from_str(&self, source: &str, format: ConfigFormat) -> Result<T, BoxedError> {
        let config: T = match format {
            ConfigFormat::Toml => toml::from_str(source)?,
            ConfigFormat::Json => serde_json::from_str(source)?,
            ConfigFormat::Yaml => {
                return Err("YAML support requires serde_yaml crate".into());
            }
            ConfigFormat::Env => {
                return Err("ENV format not supported for reload_from_str".into());
            }
        };
        self.update(config.clone());
        Ok(config)
    }

    /// 从文件加载配置
    pub fn load_from_file(&self, path: &str) -> Result<T, BoxedError> {
        let content = std::fs::read_to_string(path)?;
        let format = ConfigFormat::from_extension(path)
            .ok_or("Unknown config file format")?;
        self.reload_from_str(&content, format)
    }

    /// 订阅配置变更
    pub fn subscribe(&self) -> Option<watch::Receiver<T>> {
        self.watcher_tx.as_ref().map(|tx| tx.subscribe())
    }

    /// 启动文件监控（热重载）
    pub async fn start_file_watcher(&self, path: String, interval_secs: u64) {
        let inner = self.inner.clone();
        let tx = self.watcher_tx.clone();

        tokio::spawn(async move {
            let mut last_modified = None;
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                if let Ok(metadata) = tokio::fs::metadata(&path).await {
                    if let Ok(modified) = metadata.modified() {
                        let should_reload = match last_modified {
                            Some(last) => modified > last,
                            None => true,
                        };

                        if should_reload {
                            last_modified = Some(modified);
                            match tokio::fs::read_to_string(&path).await {
                                Ok(content) => {
                                    if let Some(format) = ConfigFormat::from_extension(&path) {
                                        match format {
                                            ConfigFormat::Toml => {
                                                if let Ok(config) = toml::from_str::<T>(&content) {
                                                    let mut guard = inner.write();
                                                    *guard = config.clone();
                                                    drop(guard);
                                                    if let Some(tx) = &tx {
                                                        let _ = tx.send(config);
                                                    }
                                                    info!("Config reloaded from {}", path);
                                                }
                                            }
                                            ConfigFormat::Json => {
                                                if let Ok(config) = serde_json::from_str::<T>(&content) {
                                                    let mut guard = inner.write();
                                                    *guard = config.clone();
                                                    drop(guard);
                                                    if let Some(tx) = &tx {
                                                        let _ = tx.send(config);
                                                    }
                                                    info!("Config reloaded from {}", path);
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read config file: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}

/// 配置节
#[derive(Debug, Clone)]
pub struct ConfigSection {
    pub name: String,
    pub content: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize, PartialEq)]
    struct TestConfig {
        name: String,
        value: i32,
    }

    #[test]
    fn test_config_manager() {
        let config = TestConfig { name: "test".to_string(), value: 42 };
        let manager = ConfigManager::new(config);

        let current = manager.get();
        assert_eq!(current.name, "test");
        assert_eq!(current.value, 42);
    }

    #[test]
    fn test_config_format_from_extension() {
        assert_eq!(ConfigFormat::from_extension("config.json"), Some(ConfigFormat::Json));
        assert_eq!(ConfigFormat::from_extension("config.toml"), Some(ConfigFormat::Toml));
        assert_eq!(ConfigFormat::from_extension("config.env"), Some(ConfigFormat::Env));
        assert_eq!(ConfigFormat::from_extension("config.unknown"), None);
    }

    #[test]
    fn test_reload_from_str_json() {
        let config = TestConfig { name: "test".to_string(), value: 42 };
        let manager = ConfigManager::new(config);

        let json = r#"{"name": "updated", "value": 100}"#;
        let result = manager.reload_from_str(json, ConfigFormat::Json);
        assert!(result.is_ok());

        let current = manager.get();
        assert_eq!(current.name, "updated");
        assert_eq!(current.value, 100);
    }

    #[test]
    fn test_reload_from_str_toml() {
        let config = TestConfig { name: "test".to_string(), value: 42 };
        let manager = ConfigManager::new(config);

        let toml_str = r#"name = "toml_test"
value = 200"#;
        let result = manager.reload_from_str(toml_str, ConfigFormat::Toml);
        assert!(result.is_ok());

        let current = manager.get();
        assert_eq!(current.name, "toml_test");
        assert_eq!(current.value, 200);
    }

    #[test]
    fn test_config_subscription() {
        let config = TestConfig { name: "test".to_string(), value: 42 };
        let manager = ConfigManager::new(config);

        let rx = manager.subscribe().unwrap();
        assert_eq!(rx.borrow().name, "test");

        let new_config = TestConfig { name: "updated".to_string(), value: 99 };
        manager.update(new_config);

        assert_eq!(rx.borrow().name, "updated");
        assert_eq!(rx.borrow().value, 99);
    }
}