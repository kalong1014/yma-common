#![deny(missing_docs)]
//! Redis连接池封装，提供高频操作的统一异步接口

use redis::aio::ConnectionManager;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

/// Redis连接配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedisConfig {
    /// Redis连接URL，格式 "redis://[user:password@]host:port[/database]"
    pub url: String,
    /// 连接池最大连接数，默认10，取值范围1-100
    pub pool_size: u32,
    /// 操作超时秒数，默认5
    pub timeout_secs: u64,
    /// 失败重试次数，默认3
    pub retry_attempts: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379/0".to_string(),
            pool_size: 10,
            timeout_secs: 5,
            retry_attempts: 3,
        }
    }
}

impl RedisConfig {
    /// 使用指定URL创建配置
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }
}

/// Redis连接池封装
#[derive(Clone)]
pub struct RedisPool {
    client: ConnectionManager,
}

impl RedisPool {
    /// 连接到Redis服务器
    ///
    /// # 参数
    /// * `config` - Redis连接配置
    ///
    /// # 返回值
    /// 成功返回RedisPool实例，失败返回错误描述
    pub async fn connect(config: &RedisConfig) -> Result<Self, String> {
        let client = redis::Client::open(config.url.as_str())
            .map_err(|e| format!("Redis URL格式错误: {}", e))?;

        let mut last_err = String::new();
        for attempt in 0..config.retry_attempts {
            match client.get_connection_manager().await {
                Ok(manager) => return Ok(Self { client: manager }),
                Err(e) => {
                    last_err = e.to_string();
                    if attempt < config.retry_attempts - 1 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!("无法连接到Redis: {}", last_err))
    }

    /// 发送PING命令检测连接
    pub async fn ping(&self) -> bool {
        let mut conn = self.client.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .is_ok()
    }

    /// 获取字符串值
    ///
    /// # 参数
    /// * `key` - 键名
    ///
    /// # 返回值
    /// Some(值) 如果key存在，None如果key不存在
    pub async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let mut conn = self.client.clone();
        redis::cmd("GET")
            .arg(key)
            .query_async::<Option<String>>(&mut conn)
            .await
            .map_err(|e| format!("GET失败: {}", e))
    }

    /// 设置字符串值
    ///
    /// # 参数
    /// * `key` - 键名
    /// * `value` - 值
    /// * `ttl_secs` - 过期秒数，None表示永不过期
    pub async fn set(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> Result<(), String> {
        let mut conn = self.client.clone();
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(value);
        if let Some(ttl) = ttl_secs {
            cmd.arg("EX").arg(ttl);
        }
        cmd.query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("SET失败: {}", e))
    }

    /// 仅当key不存在时设置值（分布式锁语义）
    ///
    /// # 返回值
    /// true表示设置成功（key不存在），false表示key已存在
    pub async fn set_nx(
        &self,
        key: &str,
        value: &str,
        ttl_secs: Option<u64>,
    ) -> Result<bool, String> {
        let mut conn = self.client.clone();
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(value).arg("NX");
        if let Some(ttl) = ttl_secs {
            cmd.arg("EX").arg(ttl);
        }
        let result: Option<String> = cmd
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("SET NX失败: {}", e))?;
        Ok(result.is_some())
    }

    /// 删除一个或多个key
    pub async fn del(&self, key: &str) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("DEL")
            .arg(key)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("DEL失败: {}", e))
    }

    /// 检查key是否存在
    pub async fn exists(&self, key: &str) -> Result<bool, String> {
        let mut conn = self.client.clone();
        redis::cmd("EXISTS")
            .arg(key)
            .query_async::<i32>(&mut conn)
            .await
            .map(|count| count > 0)
            .map_err(|e| format!("EXISTS失败: {}", e))
    }

    /// 设置key的过期时间（秒）
    pub async fn expire(&self, key: &str, ttl_secs: u64) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("EXPIRE失败: {}", e))
    }

    /// 将key的整数值加1
    pub async fn incr(&self, key: &str) -> Result<i64, String> {
        let mut conn = self.client.clone();
        redis::cmd("INCR")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| format!("INCR失败: {}", e))
    }

    /// 将key的整数值减1
    pub async fn decr(&self, key: &str) -> Result<i64, String> {
        let mut conn = self.client.clone();
        redis::cmd("DECR")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| format!("DECR失败: {}", e))
    }

    /// 获取key的剩余生存时间（秒）
    ///
    /// # 返回值
    /// 剩余秒数，-1表示无过期，-2表示key不存在
    pub async fn ttl(&self, key: &str) -> Result<i64, String> {
        let mut conn = self.client.clone();
        redis::cmd("TTL")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| format!("TTL失败: {}", e))
    }

    /// 将值序列化为JSON后存储
    ///
    /// # 参数
    /// * `key` - 键名
    /// * `value` - 可序列化的值
    /// * `ttl_secs` - 过期秒数，None表示永不过期
    pub async fn set_json<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
        ttl_secs: Option<u64>,
    ) -> Result<(), String> {
        let json_str = serde_json::to_string(value)
            .map_err(|e| format!("JSON序列化失败: {}", e))?;
        self.set(key, &json_str, ttl_secs).await
    }

    /// 获取JSON值并反序列化
    ///
    /// # 参数
    /// * `key` - 键名
    ///
    /// # 返回值
    /// Some(反序列化后的值) 如果key存在，None如果key不存在
    pub async fn get_json<T: DeserializeOwned + Send>(
        &self,
        key: &str,
    ) -> Result<Option<T>, String> {
        match self.get(key).await? {
            Some(json_str) => {
                let value: T = serde_json::from_str(&json_str)
                    .map_err(|e| format!("JSON反序列化失败: {}", e))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// 设置Hash字段
    pub async fn hset(&self, key: &str, field: &str, value: &str) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("HSET")
            .arg(key)
            .arg(field)
            .arg(value)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("HSET失败: {}", e))
    }

    /// 获取Hash字段值
    pub async fn hget(&self, key: &str, field: &str) -> Result<Option<String>, String> {
        let mut conn = self.client.clone();
        redis::cmd("HGET")
            .arg(key)
            .arg(field)
            .query_async::<Option<String>>(&mut conn)
            .await
            .map_err(|e| format!("HGET失败: {}", e))
    }

    /// 删除Hash字段
    pub async fn hdel(&self, key: &str, field: &str) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("HDEL")
            .arg(key)
            .arg(field)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("HDEL失败: {}", e))
    }

    /// 获取Hash所有字段和值
    pub async fn hgetall(&self, key: &str) -> Result<HashMap<String, String>, String> {
        let mut conn = self.client.clone();
        redis::cmd("HGETALL")
            .arg(key)
            .query_async::<HashMap<String, String>>(&mut conn)
            .await
            .map_err(|e| format!("HGETALL失败: {}", e))
    }

    /// 向列表头部推入元素
    pub async fn lpush(&self, key: &str, value: &str) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("LPUSH")
            .arg(key)
            .arg(value)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("LPUSH失败: {}", e))
    }

    /// 从列表尾部弹出元素
    pub async fn rpop(&self, key: &str) -> Result<Option<String>, String> {
        let mut conn = self.client.clone();
        redis::cmd("RPOP")
            .arg(key)
            .query_async::<Option<String>>(&mut conn)
            .await
            .map_err(|e| format!("RPOP失败: {}", e))
    }

    /// 向集合添加成员
    pub async fn sadd(&self, key: &str, member: &str) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("SADD")
            .arg(key)
            .arg(member)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("SADD失败: {}", e))
    }

    /// 获取集合所有成员
    pub async fn smembers(&self, key: &str) -> Result<Vec<String>, String> {
        let mut conn = self.client.clone();
        redis::cmd("SMEMBERS")
            .arg(key)
            .query_async::<Vec<String>>(&mut conn)
            .await
            .map_err(|e| format!("SMEMBERS失败: {}", e))
    }

    /// 发布消息到频道
    pub async fn publish(&self, channel: &str, message: &str) -> Result<(), String> {
        let mut conn = self.client.clone();
        redis::cmd("PUBLISH")
            .arg(channel)
            .arg(message)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("PUBLISH失败: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_config_default() {
        let config = RedisConfig::default();
        assert_eq!(config.url, "redis://127.0.0.1:6379/0");
        assert_eq!(config.pool_size, 10);
        assert_eq!(config.timeout_secs, 5);
        assert_eq!(config.retry_attempts, 3);
    }

    #[test]
    fn test_redis_config_from_url() {
        let config = RedisConfig::from_url("redis://localhost:6380/1");
        assert_eq!(config.url, "redis://localhost:6380/1");
        assert_eq!(config.pool_size, 10);
    }

    #[test]
    fn test_redis_config_serialization() {
        let config = RedisConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RedisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, config.url);
        assert_eq!(parsed.pool_size, config.pool_size);
    }
}