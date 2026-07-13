#![deny(missing_docs)]
//! 安全响应头模块，管理CSP、HSTS、X-Frame-Options等11个HTTP安全响应头。
//!
//! 通过配置`SecurityHeadersConfig`可以启用/禁用/自定义各个响应头的值，
//! 通过axum中间件自动注入到所有HTTP响应中。

use axum::http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

/// 安全响应头配置。
///
/// 所有字段均有安全默认值，可通过with_*方法自定义。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Content-Security-Policy响应头值
    pub content_security_policy: String,
    /// X-Frame-Options响应头值
    pub x_frame_options: String,
    /// X-Content-Type-Options响应头值
    pub x_content_type_options: String,
    /// X-XSS-Protection响应头值
    pub x_xss_protection: String,
    /// Strict-Transport-Security响应头值
    pub strict_transport_security: String,
    /// Referrer-Policy响应头值
    pub referrer_policy: String,
    /// Permissions-Policy响应头值
    pub permissions_policy: String,
    /// Cross-Origin-Opener-Policy响应头值
    pub cross_origin_opener_policy: String,
    /// Cross-Origin-Resource-Policy响应头值
    pub cross_origin_resource_policy: String,
    /// Cross-Origin-Embedder-Policy响应头值
    pub cross_origin_embedder_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            content_security_policy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string(),
            x_frame_options: "DENY".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_xss_protection: "1; mode=block".to_string(),
            strict_transport_security: "max-age=31536000; includeSubDomains".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=()".to_string(),
            cross_origin_opener_policy: "same-origin".to_string(),
            cross_origin_resource_policy: "same-origin".to_string(),
            cross_origin_embedder_policy: String::new(),
        }
    }
}

impl SecurityHeadersConfig {
    /// 设置Content-Security-Policy头值。
    ///
    /// # 参数
    /// * `policy` - CSP策略字符串
    pub fn with_csp(mut self, policy: String) -> Self {
        self.content_security_policy = policy;
        self
    }

    /// 设置Strict-Transport-Security头值。
    ///
    /// # 参数
    /// * `policy` - HSTS策略字符串
    pub fn with_hsts(mut self, policy: String) -> Self {
        self.strict_transport_security = policy;
        self
    }

    /// 设置X-Frame-Options头值。
    ///
    /// # 参数
    /// * `policy` - 取值 "DENY" 或 "SAMEORIGIN"
    pub fn with_frame(mut self, policy: String) -> Self {
        self.x_frame_options = policy;
        self
    }

    /// 禁用CSP响应头。
    pub fn disable_csp(mut self) -> Self {
        self.content_security_policy = String::new();
        self
    }

    /// 禁用HSTS响应头。
    pub fn disable_hsts(mut self) -> Self {
        self.strict_transport_security = String::new();
        self
    }
}

/// 创建安全响应头Axum中间件。
///
/// # 参数
/// * `config` - 安全响应头配置
///
/// # 返回值
/// axum middleware闭包，自动为所有响应添加配置的响应头。
pub fn security_headers_middleware(
    config: SecurityHeadersConfig,
) -> impl (Fn(axum::extract::Request, axum::middleware::Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + Send>>)
       + Clone
       + Send
       + Sync
       + 'static {
    move |request: axum::extract::Request, next: axum::middleware::Next| {
        let config = config.clone();
        Box::pin(async move {
            let response = next.run(request).await;
            apply_security_headers(response, &config)
        })
    }
}

fn apply_security_headers(
    mut response: axum::response::Response,
    config: &SecurityHeadersConfig,
) -> axum::response::Response {
    let headers = response.headers_mut();

    if !config.content_security_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.content_security_policy) {
            headers.insert(HeaderName::from_static("content-security-policy"), val);
        }
    }

    if !config.x_frame_options.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.x_frame_options) {
            headers.insert(axum::http::header::X_FRAME_OPTIONS, val);
        }
    }

    if !config.x_content_type_options.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.x_content_type_options) {
            headers.insert(axum::http::header::X_CONTENT_TYPE_OPTIONS, val);
        }
    }

    if !config.x_xss_protection.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.x_xss_protection) {
            headers.insert(axum::http::header::X_XSS_PROTECTION, val);
        }
    }

    if !config.strict_transport_security.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.strict_transport_security) {
            headers.insert(axum::http::header::STRICT_TRANSPORT_SECURITY, val);
        }
    }

    if !config.referrer_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.referrer_policy) {
            headers.insert(axum::http::header::REFERRER_POLICY, val);
        }
    }

    if !config.permissions_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.permissions_policy) {
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                val,
            );
        }
    }

    if !config.cross_origin_opener_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.cross_origin_opener_policy) {
            headers.insert(
                HeaderName::from_static("cross-origin-opener-policy"),
                val,
            );
        }
    }

    if !config.cross_origin_resource_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.cross_origin_resource_policy) {
            headers.insert(
                HeaderName::from_static("cross-origin-resource-policy"),
                val,
            );
        }
    }

    if !config.cross_origin_embedder_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.cross_origin_embedder_policy) {
            headers.insert(
                HeaderName::from_static("cross-origin-embedder-policy"),
                val,
            );
        }
    }

    response
}

/// 返回严格安全响应头配置。
///
/// # 返回值
/// X-Frame-Options为DENY、X-Content-Type-Options为nosniff的默认配置。
pub fn strict_security_headers() -> SecurityHeadersConfig {
    SecurityHeadersConfig::default()
}

/// 返回API场景的安全响应头配置。
///
/// # 返回值
/// 适合REST API使用的安全响应头配置。
pub fn api_security_headers() -> SecurityHeadersConfig {
    SecurityHeadersConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use tower::util::ServiceExt;

    #[test]
    fn test_default_config() {
        let config = SecurityHeadersConfig::default();
        assert_eq!(config.x_frame_options, "DENY");
        assert_eq!(config.x_content_type_options, "nosniff");
        assert!(config.content_security_policy.contains("default-src 'self'"));
    }

    #[test]
    fn test_with_csp() {
        let config = SecurityHeadersConfig::default()
            .with_csp("default-src 'none'".to_string());
        assert_eq!(config.content_security_policy, "default-src 'none'");
    }

    #[test]
    fn test_disable_csp() {
        let config = SecurityHeadersConfig::default().disable_csp();
        assert!(config.content_security_policy.is_empty());
    }

    #[test]
    fn test_disable_hsts() {
        let config = SecurityHeadersConfig::default().disable_hsts();
        assert!(config.strict_transport_security.is_empty());
    }

    #[test]
    fn test_with_frame() {
        let config = SecurityHeadersConfig::default()
            .with_frame("SAMEORIGIN".to_string());
        assert_eq!(config.x_frame_options, "SAMEORIGIN");
    }

    #[test]
    fn test_with_hsts() {
        let config = SecurityHeadersConfig::default()
            .with_hsts("max-age=63072000".to_string());
        assert_eq!(config.strict_transport_security, "max-age=63072000");
    }

    #[test]
    fn test_strict_security_headers() {
        let config = strict_security_headers();
        assert_eq!(config.x_frame_options, "DENY");
    }

    #[test]
    fn test_api_security_headers() {
        let config = api_security_headers();
        assert_eq!(config.referrer_policy, "strict-origin-when-cross-origin");
    }

    #[tokio::test]
    async fn test_security_headers_middleware() {
        let config = SecurityHeadersConfig::default();
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers_middleware(config)));

        use axum::body::Body;
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(headers.contains_key("content-security-policy"));
        assert_eq!(
            headers.get("x-frame-options").unwrap(),
            "DENY"
        );
    }
}