#![deny(missing_docs)]
//! CSRF防护模块，通过Token机制防止跨站请求伪造攻击。
//!
//! 使用一次性Token，验证后立即失效，防止重放攻击。

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// CSRF防护配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfConfig {
    /// 存放CSRF Token的HTTP请求头名称，默认 "x-csrf-token"
    pub token_header_name: String,
    /// 存放CSRF Token的Cookie名称，默认 "csrftoken"
    pub cookie_name: String,
    /// Token有效期（秒），默认 3600
    pub token_ttl_secs: u64,
    /// Cookie的Path属性，默认 "/"
    pub cookie_path: String,
    /// Cookie的Secure属性，默认 true
    pub cookie_secure: bool,
    /// Cookie的HttpOnly属性，默认 false
    pub cookie_http_only: bool,
    /// Cookie的SameSite属性，取值 "Strict" 或 "Lax"，默认 "Lax"
    pub cookie_same_site: String,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            token_header_name: "x-csrf-token".to_string(),
            cookie_name: "csrftoken".to_string(),
            token_ttl_secs: 3600,
            cookie_path: "/".to_string(),
            cookie_secure: true,
            cookie_http_only: false,
            cookie_same_site: "Lax".to_string(),
        }
    }
}

/// CSRF Token，64字节随机数据Base64编码。
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// Token字符串（Base64 URL-safe编码）
    pub token: String,
    /// Token创建时刻
    created_at: Instant,
}

impl CsrfToken {
    /// 生成新的CSRF Token。
    ///
    /// 使用32字节密码学安全随机数，Base64 URL-safe无填充编码。
    pub fn generate() -> Self {
        use base64::Engine;
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        Self {
            token,
            created_at: Instant::now(),
        }
    }

    /// 检查Token是否已过期。
    pub fn is_expired(&self, ttl_secs: u64) -> bool {
        self.created_at.elapsed() >= Duration::from_secs(ttl_secs)
    }
}

/// CSRF防护核心结构体。
pub struct CsrfProtection {
    config: Arc<CsrfConfig>,
    token_store: Arc<DashMap<String, CsrfToken>>,
}

impl CsrfProtection {
    /// 创建CSRF防护实例。
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            config: Arc::new(config),
            token_store: Arc::new(DashMap::new()),
        }
    }

    /// 为指定会话生成CSRF Token。
    ///
    /// 如果该会话已存在Token则覆盖。
    pub fn generate_token(&self, session_id: &str) -> String {
        let csrf_token = CsrfToken::generate();
        let token = csrf_token.token.clone();
        self.token_store
            .insert(session_id.to_string(), csrf_token);
        token
    }

    /// 验证CSRF Token。
    ///
    /// 使用常量时间比较防止时序攻击，验证成功后Token被删除（一次性）。
    pub fn validate_token(&self, token: &str, session_id: &str) -> bool {
        let stored = match self.token_store.get(session_id) {
            Some(entry) => entry,
            None => return false,
        };

        if stored.is_expired(self.config.token_ttl_secs) {
            drop(stored);
            self.token_store.remove(session_id);
            return false;
        }

        let stored_bytes = stored.token.as_bytes();
        let token_bytes = token.as_bytes();

        let is_equal = constant_time_compare(stored_bytes, token_bytes);

        drop(stored);

        if is_equal {
            self.token_store.remove(session_id);
        }

        is_equal
    }

    /// 清理已过期的Token条目。
    pub fn cleanup_expired(&self) {
        let ttl = self.config.token_ttl_secs;
        self.token_store.retain(|_, t| !t.is_expired(ttl));
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 判断HTTP方法是否为安全方法。
///
/// 安全方法: GET, HEAD, OPTIONS, TRACE
pub fn is_safe_method(method: &axum::http::Method) -> bool {
    method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
        || method == axum::http::Method::TRACE
}

/// 从请求头提取客户端IP。
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
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

/// CSRF防护Axum中间件。
pub fn csrf_middleware(
    config: Arc<CsrfConfig>,
    protection: Arc<CsrfProtection>,
) -> impl (
    Fn(
        axum::extract::Request,
        axum::middleware::Next,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + Send>>
) + Clone
       + Send
       + Sync
       + 'static {
    move |request: axum::extract::Request, next: axum::middleware::Next| {
        let config = Arc::clone(&config);
        let protection = Arc::clone(&protection);
        Box::pin(async move {
            if is_safe_method(request.method()) {
                return next.run(request).await;
            }

            let headers = request.headers();
            let token = headers
                .get(&config.token_header_name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .or_else(|| {
                    // 尝试从Cookie中获取
                    request.headers().get("cookie").and_then(|cookie_val| {
                        cookie_val.to_str().ok().and_then(|cookies| {
                            parse_cookie_value(cookies, &config.cookie_name)
                        })
                    })
                });

            let token = match token {
                Some(t) => t,
                None => {
                    return build_csrf_error_response("CSRF Token 缺失");
                }
            };

            let session_id = "default".to_string();

            if !protection.validate_token(&token, &session_id) {
                return build_csrf_error_response("CSRF Token 无效或已过期");
            }

            next.run(request).await
        })
    }
}

fn parse_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let name = &part[..eq_pos].trim();
            if *name == cookie_name {
                return Some(part[eq_pos + 1..].trim().to_string());
            }
        }
    }
    None
}

fn build_csrf_error_response(message: &str) -> axum::response::Response {
    use axum::body::Body;
    let body = serde_json::json!({
        "code": 403,
        "message": message,
    })
    .to_string();
    axum::response::Response::builder()
        .status(axum::http::StatusCode::FORBIDDEN)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .body(Body::from(body))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_config_default() {
        let config = CsrfConfig::default();
        assert_eq!(config.token_header_name, "x-csrf-token");
        assert_eq!(config.token_ttl_secs, 3600);
        assert_eq!(config.cookie_name, "csrftoken");
    }

    #[test]
    fn test_csrf_token_generate() {
        let token = CsrfToken::generate();
        assert!(!token.token.is_empty());
        assert!(token.token.len() > 30);
    }

    #[test]
    fn test_token_not_expired() {
        let token = CsrfToken::generate();
        assert!(!token.is_expired(3600));
    }

    #[test]
    fn test_token_generation_produces_unique() {
        let t1 = CsrfToken::generate();
        let t2 = CsrfToken::generate();
        assert_ne!(t1.token, t2.token);
    }

    #[test]
    fn test_protection_generate_and_validate() {
        let protection = CsrfProtection::new(CsrfConfig::default());
        let token = protection.generate_token("session-1");
        assert!(protection.validate_token(&token, "session-1"));
    }

    #[test]
    fn test_protection_validate_invalid_session() {
        let protection = CsrfProtection::new(CsrfConfig::default());
        protection.generate_token("session-1");
        assert!(!protection.validate_token("wrong-token", "session-1"));
    }

    #[test]
    fn test_protection_token_one_time_use() {
        let protection = CsrfProtection::new(CsrfConfig::default());
        let token = protection.generate_token("session-1");
        assert!(protection.validate_token(&token, "session-1"));
        // 第二次验证应该失败（Token已被消耗）
        assert!(!protection.validate_token(&token, "session-1"));
    }

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_compare_different() {
        assert!(!constant_time_compare(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_compare_different_length() {
        assert!(!constant_time_compare(b"hello", b"hell"));
    }

    #[test]
    fn test_is_safe_method() {
        assert!(is_safe_method(&axum::http::Method::GET));
        assert!(is_safe_method(&axum::http::Method::HEAD));
        assert!(is_safe_method(&axum::http::Method::OPTIONS));
        assert!(!is_safe_method(&axum::http::Method::POST));
        assert!(!is_safe_method(&axum::http::Method::DELETE));
    }

    #[test]
    fn test_parse_cookie_value_found() {
        let result = parse_cookie_value("a=1; csrftoken=abc123; b=2", "csrftoken");
        assert_eq!(result, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_cookie_value_not_found() {
        let result = parse_cookie_value("a=1; b=2", "csrftoken");
        assert_eq!(result, None);
    }
}