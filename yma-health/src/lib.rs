#![deny(missing_docs)]
//! 健康检查模块，提供可扩展的HealthCheck trait和各检查项实现。
//!
//! # Features
//! - `db`: 启用数据库连接健康检查
//! - `redis-check`: 启用Redis连接健康检查

use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

/// 单项健康检查状态。
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckItem {
    /// 检查项名称
    pub name: String,
    /// 检查状态: "pass" 或 "fail"
    pub status: String,
    /// 失败时的详细描述
    pub message: Option<String>,
    /// 检查耗时（毫秒）
    pub latency_ms: u64,
}

/// 全局健康状态。
#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    /// 全局状态: "ok", "degraded", "down"
    pub status: String,
    /// 服务版本号
    pub version: String,
    /// 进程已运行秒数
    pub uptime_seconds: u64,
    /// 各检查项的结果列表
    pub checks: Vec<HealthCheckItem>,
}

/// 健康检查trait。
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    /// 返回检查项名称。
    fn name(&self) -> &str;
    /// 异步执行健康检查。
    async fn check(&self) -> HealthCheckItem;
}

/// 健康检查管理器。
pub struct HealthChecker {
    start_time: Instant,
    checks: Vec<Box<dyn HealthCheck + Send + Sync>>,
}

impl HealthChecker {
    /// 创建空的健康检查管理器。
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            checks: Vec::new(),
        }
    }

    /// 添加一个健康检查项。
    pub fn add_check(&mut self, check: Box<dyn HealthCheck + Send + Sync>) -> &mut Self {
        self.checks.push(check);
        self
    }

    /// 执行所有健康检查并返回全局状态。
    pub async fn check_all(&self) -> HealthStatus {
        let mut results = Vec::new();

        for check in &self.checks {
            results.push(check.check().await);
        }

        let pass_count = results.iter().filter(|r| r.status == "pass").count();
        let fail_count = results.len() - pass_count;

        let status = if results.is_empty() || fail_count == 0 {
            "ok"
        } else if pass_count > 0 {
            "degraded"
        } else {
            "down"
        };

        HealthStatus {
            status: status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            checks: results,
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum健康检查handler。
pub async fn health_handler(
    axum::extract::State(checker): axum::extract::State<Arc<HealthChecker>>,
) -> axum::Json<HealthStatus> {
    axum::Json(checker.check_all().await)
}

#[cfg(feature = "db")]
mod db_check {
    use super::*;
    use std::time::Instant;

    /// 数据库连接健康检查。
    pub struct DatabaseHealthCheck {
        pool: sqlx::PgPool,
    }

    impl DatabaseHealthCheck {
        /// 创建数据库健康检查。
        pub fn new(pool: sqlx::PgPool) -> Self {
            Self { pool }
        }
    }

    #[async_trait::async_trait]
    impl HealthCheck for DatabaseHealthCheck {
        fn name(&self) -> &str {
            "database"
        }

        async fn check(&self) -> HealthCheckItem {
            let start = Instant::now();
            let result = self.pool.acquire().await;
            let latency_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(_conn) => {
                    if latency_ms > 5000 {
                        HealthCheckItem {
                            name: self.name().to_string(),
                            status: "fail".to_string(),
                            message: Some(format!("数据库连接超时: {}ms", latency_ms)),
                            latency_ms,
                        }
                    } else {
                        HealthCheckItem {
                            name: self.name().to_string(),
                            status: "pass".to_string(),
                            message: None,
                            latency_ms,
                        }
                    }
                }
                Err(e) => HealthCheckItem {
                    name: self.name().to_string(),
                    status: "fail".to_string(),
                    message: Some(format!("数据库连接失败: {}", e)),
                    latency_ms,
                },
            }
        }
    }
}

#[cfg(feature = "db")]
pub use db_check::DatabaseHealthCheck;

#[cfg(feature = "redis-check")]
mod redis_check {
    use super::*;
    use std::time::Instant;
    use tokio::time::timeout;

    /// Redis连接健康检查。
    pub struct RedisHealthCheck {
        client: redis::aio::ConnectionManager,
    }

    impl RedisHealthCheck {
        /// 创建Redis健康检查。
        pub fn new(client: redis::aio::ConnectionManager) -> Self {
            Self { client }
        }
    }

    #[async_trait::async_trait]
    impl HealthCheck for RedisHealthCheck {
        fn name(&self) -> &str {
            "redis"
        }

        async fn check(&self) -> HealthCheckItem {
            let start = Instant::now();
            let mut conn = self.client.clone();
            let result = timeout(
                std::time::Duration::from_secs(3),
                redis::cmd("PING").query_async::<String>(&mut conn),
            )
            .await;
            let latency_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(Ok(response)) if response == "PONG" => HealthCheckItem {
                    name: self.name().to_string(),
                    status: "pass".to_string(),
                    message: None,
                    latency_ms,
                },
                Ok(Ok(_)) => HealthCheckItem {
                    name: self.name().to_string(),
                    status: "fail".to_string(),
                    message: Some("Redis返回非预期响应".to_string()),
                    latency_ms,
                },
                Ok(Err(e)) => HealthCheckItem {
                    name: self.name().to_string(),
                    status: "fail".to_string(),
                    message: Some(format!("Redis连接失败: {}", e)),
                    latency_ms,
                },
                Err(_) => HealthCheckItem {
                    name: self.name().to_string(),
                    status: "fail".to_string(),
                    message: Some("Redis连接超时（3秒）".to_string()),
                    latency_ms,
                },
            }
        }
    }
}

#[cfg(feature = "redis-check")]
pub use redis_check::RedisHealthCheck;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHealthCheck {
        name: String,
        should_pass: bool,
        latency_ms: u64,
    }

    #[async_trait::async_trait]
    impl HealthCheck for MockHealthCheck {
        fn name(&self) -> &str {
            &self.name
        }

        async fn check(&self) -> HealthCheckItem {
            HealthCheckItem {
                name: self.name.clone(),
                status: if self.should_pass {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                message: if self.should_pass {
                    None
                } else {
                    Some("模拟失败".to_string())
                },
                latency_ms: self.latency_ms,
            }
        }
    }

    #[tokio::test]
    async fn test_all_checks_pass() {
        let mut checker = HealthChecker::new();
        checker
            .add_check(Box::new(MockHealthCheck {
                name: "test1".to_string(),
                should_pass: true,
                latency_ms: 10,
            }))
            .add_check(Box::new(MockHealthCheck {
                name: "test2".to_string(),
                should_pass: true,
                latency_ms: 5,
            }));

        let status = checker.check_all().await;
        assert_eq!(status.status, "ok");
        assert_eq!(status.checks.len(), 2);
        assert_eq!(status.checks[0].status, "pass");
    }

    #[tokio::test]
    async fn test_one_check_fails() {
        let mut checker = HealthChecker::new();
        checker
            .add_check(Box::new(MockHealthCheck {
                name: "test1".to_string(),
                should_pass: true,
                latency_ms: 10,
            }))
            .add_check(Box::new(MockHealthCheck {
                name: "test2".to_string(),
                should_pass: false,
                latency_ms: 100,
            }));

        let status = checker.check_all().await;
        assert_eq!(status.status, "degraded");
    }

    #[tokio::test]
    async fn test_all_checks_fail() {
        let mut checker = HealthChecker::new();
        checker.add_check(Box::new(MockHealthCheck {
            name: "test1".to_string(),
            should_pass: false,
            latency_ms: 10,
        }));

        let status = checker.check_all().await;
        assert_eq!(status.status, "down");
    }

    #[tokio::test]
    async fn test_empty_checker() {
        let checker = HealthChecker::new();
        let status = checker.check_all().await;
        assert_eq!(status.status, "ok");
        assert_eq!(status.checks.len(), 0);
    }

    #[test]
    fn test_health_check_item_serializable() {
        let item = HealthCheckItem {
            name: "test".to_string(),
            status: "pass".to_string(),
            message: None,
            latency_ms: 25,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("pass"));
    }
}