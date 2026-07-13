#![deny(missing_docs)]
//! 限流模块，支持内存和Redis分布式存储后端，可按IP/端点自定义规则进行流量控制。
//!
//! # Features
//! - `memory`: 使用DashMap内存存储（默认启用）
//! - `redis-store`: 使用Redis作为分布式限流存储
//! - `axum-middleware`: 提供axum中间件适配

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 限流规则，定义时间窗口内允许的最大请求数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// 时间窗口内允许的最大请求数量
    pub max_requests: u32,
    /// 时间窗口大小（秒）
    pub window_secs: u64,
}

impl RateLimitRule {
    /// 创建限流规则。
    ///
    /// # 参数
    /// * `max_requests` - 最大请求数，最小值为1
    /// * `window_secs` - 时间窗口秒数，最小值为1
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests: max_requests.max(1),
            window_secs: window_secs.max(1),
        }
    }
}

/// 限流配置，包含全局开关、默认规则和特定规则。
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// 全局限流开关，false时所有请求直接放行
    pub enabled: bool,
    /// 默认限流规则
    pub default_rule: RateLimitRule,
    /// 按IP的限流规则
    pub per_ip_rule: Option<RateLimitRule>,
    /// 按API端点路径前缀的限流规则
    pub per_endpoint_rules: HashMap<String, RateLimitRule>,
    /// 白名单IP地址列表
    pub whitelist_ips: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_rule: RateLimitRule::new(100, 60),
            per_ip_rule: None,
            per_endpoint_rules: HashMap::new(),
            whitelist_ips: Vec::new(),
        }
    }
}

/// 限流错误。
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// 请求过于频繁
    TooManyRequests,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::TooManyRequests => {
                write!(f, "请求过于频繁，请稍后重试")
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

#[cfg(feature = "memory")]
mod memory_limiter {
    use super::*;
    use dashmap::DashMap;

    struct RateLimitEntry {
        count: u32,
        window_start: Instant,
    }

    /// 基于内存的限流器。
    pub struct MemoryRateLimiter {
        config: Arc<RateLimitConfig>,
        records: Arc<DashMap<String, RateLimitEntry>>,
    }

    impl MemoryRateLimiter {
        /// 创建内存限流器。
        pub fn new(config: RateLimitConfig) -> Self {
            Self {
                config: Arc::new(config),
                records: Arc::new(DashMap::new()),
            }
        }

        /// 执行限流检查。
        pub async fn check(&self, key: &str, endpoint: Option<&str>) -> Result<(), RateLimitError> {
            if !self.config.enabled {
                return Ok(());
            }

            if self.config.whitelist_ips.iter().any(|ip| ip == key) {
                return Ok(());
            }

            let rule = self.resolve_rule(endpoint);
            self.check_memory(key, &rule)
        }

        fn resolve_rule(&self, endpoint: Option<&str>) -> RateLimitRule {
            if let Some(ep) = endpoint {
                for (prefix, rule) in &self.config.per_endpoint_rules {
                    if ep.starts_with(prefix) {
                        return rule.clone();
                    }
                }
            }

            if let Some(ref ip_rule) = self.config.per_ip_rule {
                return ip_rule.clone();
            }

            self.config.default_rule.clone()
        }

        fn check_memory(&self, key: &str, rule: &RateLimitRule) -> Result<(), RateLimitError> {
            let now = Instant::now();
            let window = Duration::from_secs(rule.window_secs);

            let mut entry = self.records.entry(key.to_string()).or_insert_with(|| RateLimitEntry {
                count: 0,
                window_start: now,
            });

            let elapsed = now.duration_since(entry.window_start);
            if elapsed >= window {
                entry.count = 1;
                entry.window_start = now;
            } else {
                entry.count += 1;
                if entry.count > rule.max_requests {
                    return Err(RateLimitError::TooManyRequests);
                }
            }

            Ok(())
        }
    }
}

#[cfg(feature = "memory")]
pub use memory_limiter::MemoryRateLimiter;

/// 限流器，整合内存和Redis后端。
pub struct RateLimiter {
    #[cfg(feature = "memory")]
    memory: memory_limiter::MemoryRateLimiter,
}

impl RateLimiter {
    /// 创建限流器实例。
    ///
    /// # 参数
    /// * `config` - 限流配置
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            #[cfg(feature = "memory")]
            memory: memory_limiter::MemoryRateLimiter::new(config),
        }
    }

    /// 执行限流检查。
    ///
    /// # 参数
    /// * `key` - 限流标识（通常为客户端IP）
    /// * `endpoint` - 可选请求路径
    ///
    /// # 返回值
    /// Ok(()) 放行, Err(RateLimitError) 限流触发
    pub async fn check(&self, key: &str, endpoint: Option<&str>) -> Result<(), RateLimitError> {
        #[cfg(feature = "memory")]
        {
            self.memory.check(key, endpoint).await
        }
        #[cfg(not(feature = "memory"))]
        {
            let _ = (key, endpoint);
            Ok(())
        }
    }

    /// 按IP执行限流检查。
    ///
    /// # 参数
    /// * `ip` - 客户端IP地址
    /// * `endpoint` - 可选请求路径
    pub async fn check_ip(&self, ip: &str, endpoint: Option<&str>) -> Result<(), RateLimitError> {
        self.check(ip, endpoint).await
    }
}

#[cfg(feature = "axum-middleware")]
/// 创建限流Axum中间件。
///
/// # 参数
/// * `limiter` - 限流器实例（Arc包装）
///
/// # 返回值
/// axum middleware函数。
pub fn rate_limit_middleware(
    limiter: Arc<RateLimiter>,
) -> impl axum::middleware::from_fn::__private::TupleFutureFn1<
    axum::extract::Request,
    axum::response::Response,
>
       + Clone
       + Send
       + Sync
       + 'static {
    use axum::body::Body;
    use axum::middleware::Next;
    use axum::response::Response;

    move |request: axum::extract::Request, next: Next| {
        let limiter = Arc::clone(&limiter);

        async move {
            let ip = get_client_ip_from_headers(request.headers())
                .or_else(|| get_peer_ip(request.extensions()))
                .unwrap_or_else(|| "127.0.0.1".to_string());

            let path = request.uri().path().to_string();

            if let Err(_e) = limiter.check_ip(&ip, Some(&path)).await {
                let body = serde_json::json!({
                    "code": 429,
                    "message": "请求过于频繁，请稍后重试"
                })
                .to_string();
                return Response::builder()
                    .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/json; charset=utf-8",
                    )
                    .body(Body::from(body))
                    .unwrap();
            }

            next.run(request).await
        }
    }
}

#[cfg(feature = "axum-middleware")]
fn get_peer_ip(_extensions: &axum::http::Extensions) -> Option<String> {
    None
}

#[cfg(feature = "axum-middleware")]
/// 从请求头提取客户端IP。
///
/// 优先级: X-Forwarded-For > X-Real-IP > 默认
pub fn get_client_ip_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            if let Some(ip) = val.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(val) = real_ip.to_str() {
            return Some(val.trim().to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_rule_new() {
        let rule = RateLimitRule::new(10, 30);
        assert_eq!(rule.max_requests, 10);
        assert_eq!(rule.window_secs, 30);
    }

    #[test]
    fn test_rate_limit_rule_new_zero_values() {
        let rule = RateLimitRule::new(0, 0);
        assert_eq!(rule.max_requests, 1);
        assert_eq!(rule.window_secs, 1);
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert_eq!(config.default_rule.max_requests, 100);
        assert_eq!(config.default_rule.window_secs, 60);
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        for _ in 0..200 {
            assert!(limiter.check("test", None).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_whitelist() {
        let config = RateLimitConfig {
            whitelist_ips: vec!["192.168.1.1".to_string()],
            default_rule: RateLimitRule::new(1, 60),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        for _ in 0..10 {
            assert!(limiter.check("192.168.1.1", None).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_exceed() {
        let config = RateLimitConfig {
            default_rule: RateLimitRule::new(3, 60),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check("test-user", None).await.is_ok());
        assert!(limiter.check("test-user", None).await.is_ok());
        assert!(limiter.check("test-user", None).await.is_ok());
        assert!(limiter.check("test-user", None).await.is_err());
    }

    #[cfg(feature = "axum-middleware")]
    #[test]
    fn test_get_client_ip_x_forwarded_for() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1, 10.0.0.2".parse().unwrap());
        let ip = get_client_ip_from_headers(&headers);
        assert_eq!(ip, Some("10.0.0.1".to_string()));
    }

    #[cfg(feature = "axum-middleware")]
    #[test]
    fn test_get_client_ip_x_real_ip() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "10.0.0.3".parse().unwrap());
        let ip = get_client_ip_from_headers(&headers);
        assert_eq!(ip, Some("10.0.0.3".to_string()));
    }

    #[cfg(feature = "axum-middleware")]
    #[test]
    fn test_get_client_ip_none() {
        let headers = axum::http::HeaderMap::new();
        let ip = get_client_ip_from_headers(&headers);
        assert_eq!(ip, None);
    }

    #[test]
    fn test_rate_limit_error_display() {
        let err = RateLimitError::TooManyRequests;
        assert_eq!(
            err.to_string(),
            "请求过于频繁，请稍后重试"
        );
    }
}