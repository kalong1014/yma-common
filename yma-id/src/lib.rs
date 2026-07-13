#![deny(missing_docs)]
//! ID生成器模块，提供UUID v4/v7生成和Snowflake分布式ID算法。
//!
//! # Features
//! - `v4`: 启用UUID v4随机ID生成（默认启用）
//! - `v7`: 启用UUID v7时间排序ID生成
//! - `snowflake`: 启用Snowflake分布式ID生成器

/// 生成UUID v4格式的ID字符串。
///
/// # 返回值
/// 小写连字符格式的UUID字符串，如 "550e8400-e29b-41d4-a716-446655440000"。
#[cfg(feature = "v4")]
pub fn generate_uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// 生成UUID v7格式的ID字符串（基于时间戳）。
///
/// # 返回值
/// 小写连字符格式的UUID v7字符串。
#[cfg(feature = "v7")]
pub fn generate_uuid_v7() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// 生成不含连字符的32位十六进制ID字符串。
///
/// # 返回值
/// 32位小写十六进制字符串。
pub fn generate_simple_id() -> String {
    uuid::Uuid::new_v4().as_simple().to_string()
}

/// Snowflake分布式ID生成器。
///
/// 结构: 41位时间戳(毫秒) + 5位数据中心ID + 10位工作节点ID + 12位序列号
#[cfg(feature = "snowflake")]
pub struct SnowflakeGenerator {
    worker_id: u16,
    datacenter_id: u16,
    sequence: u16,
    last_timestamp: i64,
    epoch: i64,
}

#[cfg(feature = "snowflake")]
impl SnowflakeGenerator {
    const MAX_WORKER_ID: u16 = 1023;
    const MAX_DATACENTER_ID: u16 = 31;
    const MAX_SEQUENCE: u16 = 4095;

    /// 创建Snowflake生成器实例。
    ///
    /// # 参数
    /// * `worker_id` - 工作节点标识，取值范围0-1023
    /// * `datacenter_id` - 数据中心标识，取值范围0-31
    ///
    /// # Panics
    /// 如果worker_id大于1023或datacenter_id大于31。
    pub fn new(worker_id: u16, datacenter_id: u16) -> Self {
        assert!(
            worker_id <= Self::MAX_WORKER_ID,
            "worker_id must be 0-1023"
        );
        assert!(
            datacenter_id <= Self::MAX_DATACENTER_ID,
            "datacenter_id must be 0-31"
        );
        Self {
            worker_id,
            datacenter_id,
            sequence: 0,
            last_timestamp: -1,
            epoch: 1700000000000,
        }
    }

    /// 创建Snowflake生成器实例并指定自定义纪元。
    ///
    /// # 参数
    /// * `worker_id` - 工作节点标识，取值范围0-1023
    /// * `datacenter_id` - 数据中心标识，取值范围0-31
    /// * `epoch` - 自定义纪元起始毫秒时间戳，必须大于0
    ///
    /// # Panics
    /// 如果worker_id大于1023、datacenter_id大于31或epoch不大于0。
    pub fn with_epoch(worker_id: u16, datacenter_id: u16, epoch: i64) -> Self {
        assert!(
            worker_id <= Self::MAX_WORKER_ID,
            "worker_id must be 0-1023"
        );
        assert!(
            datacenter_id <= Self::MAX_DATACENTER_ID,
            "datacenter_id must be 0-31"
        );
        assert!(epoch > 0, "epoch must be positive");
        Self {
            worker_id,
            datacenter_id,
            sequence: 0,
            last_timestamp: -1,
            epoch,
        }
    }

    /// 生成下一个Snowflake ID。
    ///
    /// # 返回值
    /// Ok(i64) - 生成的Snowflake ID值
    /// Err(String) - 时钟回拨时的错误信息
    pub fn next_id(&mut self) -> Result<i64, String> {
        let current_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("获取系统时间失败: {e}"))?
            .as_millis() as i64;

        if current_ms < self.last_timestamp {
            return Err(format!(
                "时钟回拨检测: 当前时间戳 {} 小于上次时间戳 {}，差值 {} 毫秒",
                current_ms,
                self.last_timestamp,
                self.last_timestamp - current_ms
            ));
        }

        if current_ms == self.last_timestamp {
            self.sequence = self.sequence.wrapping_add(1);
            if self.sequence > Self::MAX_SEQUENCE {
                loop {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as i64;
                    if now > self.last_timestamp {
                        break;
                    }
                }
                self.sequence = 0;
                return self.next_id();
            }
        } else {
            self.sequence = 0;
        }

        self.last_timestamp = current_ms;

        let id = ((current_ms - self.epoch) << 22)
            | ((self.datacenter_id as i64) << 17)
            | ((self.worker_id as i64) << 12)
            | (self.sequence as i64);

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_simple_id() {
        let id1 = generate_simple_id();
        let id2 = generate_simple_id();
        assert_eq!(id1.len(), 32);
        assert_ne!(id1, id2);
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_uuid_v4() {
        let id1 = generate_uuid_v4();
        let id2 = generate_uuid_v4();
        assert_eq!(id1.len(), 36);
        assert_ne!(id1, id2);
    }

    #[cfg(feature = "v7")]
    #[test]
    fn test_generate_uuid_v7() {
        let id1 = generate_uuid_v7();
        let id2 = generate_uuid_v7();
        assert_eq!(id1.len(), 36);
        assert_ne!(id1, id2);
    }

    #[cfg(feature = "snowflake")]
    #[test]
    fn test_snowflake_new() {
        let gen = SnowflakeGenerator::new(1, 2);
        assert_eq!(gen.worker_id, 1);
        assert_eq!(gen.datacenter_id, 2);
    }

    #[cfg(feature = "snowflake")]
    #[test]
    fn test_snowflake_next_id() {
        let mut gen = SnowflakeGenerator::new(1, 2);
        let id1 = gen.next_id().unwrap();
        let id2 = gen.next_id().unwrap();
        assert!(id1 > 0);
        assert!(id2 > id1);
    }

    #[cfg(feature = "snowflake")]
    #[test]
    fn test_snowflake_unique_ids() {
        let mut gen = SnowflakeGenerator::new(1, 2);
        let mut ids = Vec::new();
        for _ in 0..100 {
            ids.push(gen.next_id().unwrap());
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 100);
    }

    #[cfg(feature = "snowflake")]
    #[test]
    #[should_panic(expected = "worker_id must be 0-1023")]
    fn test_snowflake_invalid_worker_id() {
        SnowflakeGenerator::new(1024, 0);
    }

    #[cfg(feature = "snowflake")]
    #[test]
    #[should_panic(expected = "datacenter_id must be 0-31")]
    fn test_snowflake_invalid_datacenter_id() {
        SnowflakeGenerator::new(0, 32);
    }

    #[cfg(feature = "snowflake")]
    #[test]
    fn test_snowflake_with_epoch() {
        let mut gen = SnowflakeGenerator::with_epoch(1, 2, 1700000000000);
        let id = gen.next_id().unwrap();
        assert!(id > 0);
    }
}