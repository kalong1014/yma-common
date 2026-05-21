//! yma-storage 存储抽象统一库
//!
//! 提供统一存储接口，支持内存/文件/Redis/SQLx 多种后端
//! 版本锁定: 0.2.0

use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::fs;

/// 存储错误
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Item not found: {0}")]
    NotFound(String),
    #[error("Storage error: {0}")]
    Internal(String),
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// 存储键值对
#[derive(Debug, Clone)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub content_type: String,
}

/// 存储后端特征
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    async fn exists(&self, key: &str) -> Result<bool, StorageError>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError>;
}

// ============ 内存存储后端 ============

pub struct MemoryStorage {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.data.read().get(key).cloned())
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.data.write().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.data.write().remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.data.read().contains_key(key))
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let data = self.data.read();
        let keys: Vec<String> = data
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        Ok(keys)
    }
}

// ============ 文件系统存储后端 ============

pub struct FileSystemStorage {
    base_path: PathBuf,
}

impl FileSystemStorage {
    pub fn new(base_path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = base_path.as_ref().to_path_buf();
        fs::create_dir_all(&path)
            .map_err(|e| StorageError::Internal(format!("Failed to create directory: {}", e)))?;
        Ok(Self { base_path: path })
    }

    fn key_to_path(&self, key: &str) -> PathBuf {
        // 将 key 中的特殊字符替换为安全的路径
        let safe_key = key.replace('/', "_").replace('\\', "_");
        self.base_path.join(&safe_key)
    }
}

#[async_trait]
impl StorageBackend for FileSystemStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.key_to_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let data = tokio::fs::read(&path)
            .await
            .map_err(|e| StorageError::Internal(format!("Read failed: {}", e)))?;
        Ok(Some(data))
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let path = self.key_to_path(key);
        tokio::fs::write(&path, value)
            .await
            .map_err(|e| StorageError::Internal(format!("Write failed: {}", e)))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.key_to_path(key);
        if path.exists() {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| StorageError::Internal(format!("Delete failed: {}", e)))?;
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let path = self.key_to_path(key);
        Ok(path.exists())
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let mut keys = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| StorageError::Internal(format!("List failed: {}", e)))?;

        while let Some(entry) = entries.next_entry()
            .await
            .map_err(|e| StorageError::Internal(format!("List failed: {}", e)))?
        {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(prefix) {
                    keys.push(name.to_string());
                }
            }
        }
        Ok(keys)
    }
}

// ============ 存储管理器 ============

pub struct StorageManager {
    backend: Arc<dyn StorageBackend>,
}

impl StorageManager {
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self { backend }
    }

    /// 创建内存存储
    pub fn memory() -> Self {
        Self::new(Arc::new(MemoryStorage::new()))
    }

    /// 创建文件系统存储
    pub fn filesystem(base_path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Ok(Self::new(Arc::new(FileSystemStorage::new(base_path)?)))
    }

    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.backend.get(key).await
    }

    pub async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.backend.set(key, value).await
    }

    pub async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.backend.delete(key).await
    }

    pub async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        self.backend.exists(key).await
    }

    pub async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        self.backend.list_keys(prefix).await
    }

    /// 存储 JSON 序列化对象
    pub async fn set_json<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), StorageError> {
        let json = serde_json::to_vec(value)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.set(key, &json).await
    }

    /// 读取 JSON 反序列化对象
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StorageError> {
        match self.get(key).await? {
            Some(data) => {
                let value = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new();
        storage.set("key1", b"value1").await.unwrap();

        let value = storage.get("key1").await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        assert!(storage.exists("key1").await.unwrap());
        storage.delete("key1").await.unwrap();
        assert!(!storage.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_filesystem_storage() {
        let temp_dir = std::env::temp_dir().join("yma_storage_test");
        let storage = FileSystemStorage::new(&temp_dir).unwrap();

        storage.set("test_key", b"test_value").await.unwrap();
        let value = storage.get("test_key").await.unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));

        // 清理
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_storage_manager_json() {
        let manager = StorageManager::memory();

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
        struct TestData {
            name: String,
            value: i32,
        }

        let data = TestData { name: "test".to_string(), value: 42 };
        manager.set_json("data", &data).await.unwrap();

        let retrieved: Option<TestData> = manager.get_json("data").await.unwrap();
        assert_eq!(retrieved, Some(data));
    }
}