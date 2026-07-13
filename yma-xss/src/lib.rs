#![deny(missing_docs)]
//! XSS防护模块，提供HTML转义、纯文本净化、富文本净化和JSON请求体过滤。
//!
//! # Features
//! - `axum-middleware`: 启用axum中间件自动过滤JSON请求体中的XSS内容

use regex::Regex;
use std::sync::LazyLock;

/// 将HTML特殊字符转义为实体编码。
///
/// # 参数
/// * `input` - 原始输入字符串
///
/// # 返回值
/// <、>、&、"、' 被替换为对应实体编码后的字符串。
pub fn html_escape(input: &str) -> String {
    html_escape::encode_text(input).to_string()
}

/// 移除所有HTML标签，仅保留纯文本内容。
///
/// # 参数
/// * `input` - 可能含HTML标签的输入
///
/// # 返回值
/// 去除所有HTML标签和属性后的纯文本字符串。
pub fn sanitize_plain_text(input: &str) -> String {
    ammonia::Builder::empty()
        .clean(input)
        .to_string()
}

/// 保留安全HTML富文本标签，移除危险标签和事件处理器。
///
/// 保留标签: a, p, br, strong, em, u, ul, ol, li, blockquote,
///   img, h1-h4, pre, code, table, tr, td, th
/// a标签额外允许: href(http/https/mailto), target, rel
/// img标签额外允许: src(http/https), alt, width, height
/// 禁止: style属性、on*事件处理器、script/iframe/object/embed/svg/link/meta标签
///
/// # 参数
/// * `input` - 原始HTML富文本
///
/// # 返回值
/// 净化后仅保留安全标签和属性的HTML字符串。
pub fn sanitize_rich_text(input: &str) -> String {
    let mut builder = ammonia::Builder::default();

    builder
        .add_tags(&[
            "a", "p", "br", "strong", "em", "u", "ul", "ol", "li",
            "blockquote", "img", "h1", "h2", "h3", "h4", "pre", "code",
            "table", "tr", "td", "th",
        ])
        .add_generic_attributes(&["id", "class", "title"])
        .add_tag_attributes("a", &["href", "target"])
        .add_tag_attributes("img", &["src", "alt", "width", "height"])
        .url_relative(ammonia::UrlRelative::Deny);

    let cleaned = builder.clean(input).to_string();

    let result = remove_style_attributes(&cleaned);
    remove_event_handlers(&result)
}

static STYLE_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\s*style\s*=\s*"[^"]*""#).unwrap());

static EVENT_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\s*on\w+\s*=\s*"[^"]*""#).unwrap());

fn remove_style_attributes(html: &str) -> String {
    STYLE_ATTR_RE.replace_all(html, "").to_string()
}

fn remove_event_handlers(html: &str) -> String {
    EVENT_ATTR_RE.replace_all(html, "").to_string()
}

static DANGEROUS_KEYWORDS: LazyLock<Vec<&str>> = LazyLock::new(|| {
    vec!["script", "iframe", "img", "svg", "onload", "onerror", "javascript", "onclick", "onmouse"]
});

static RICH_TEXT_TAGS: LazyLock<Vec<&str>> = LazyLock::new(|| {
    vec!["<p", "<br", "<strong", "<em", "<ul", "<ol", "<li", "<blockquote", "<h1", "<h2", "<h3", "<h4", "<table", "<a"]
});

/// 对JSON请求体的所有字符串值递归执行XSS净化处理。
///
/// # 参数
/// * `body` - JSON格式的请求体字符串
///
/// # 返回值
/// Ok(String) - 净化后的JSON字符串
/// Err(String) - JSON解析失败
pub fn sanitize_json_body(body: &str) -> Result<String, String> {
    let mut value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("JSON解析失败: {}", e))?;

    sanitize_value(&mut value);

    serde_json::to_string(&value).map_err(|e| format!("JSON序列化失败: {}", e))
}

fn sanitize_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            let sanitized = detect_and_sanitize(s);
            *s = sanitized;
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                sanitize_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                sanitize_value(v);
            }
        }
        _ => {}
    }
}

fn detect_and_sanitize(input: &str) -> String {
    if !input.contains('<') {
        return input.to_string();
    }

    let lower = input.to_lowercase();

    let is_dangerous = DANGEROUS_KEYWORDS
        .iter()
        .any(|k| lower.contains(k));

    if is_dangerous {
        return sanitize_plain_text(input);
    }

    let is_rich_text = RICH_TEXT_TAGS
        .iter()
        .any(|tag| lower.contains(tag));

    if is_rich_text {
        sanitize_rich_text(input)
    } else {
        html_escape(input)
    }
}

#[cfg(feature = "axum-middleware")]
/// XSS过滤Axum中间件。
///
/// 自动对POST/PUT/PATCH请求的JSON body进行XSS净化。
///
/// # 返回值
/// axum middleware函数。
pub fn xss_filter_middleware() -> impl axum::middleware::from_fn::__private::TupleFutureFn1<
    axum::extract::Request,
    axum::response::Response,
>
       + Clone
       + Send
       + Sync
       + 'static {
    use axum::{body::Body, http::Request, middleware::Next, response::Response};

    |request: Request, next: Next| async move {
        if request.method() != axum::http::Method::POST
            && request.method() != axum::http::Method::PUT
            && request.method() != axum::http::Method::PATCH
        {
            return next.run(request).await;
        }

        let content_type = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("application/json") {
            return next.run(request).await;
        }

        let (parts, body) = request.into_parts();

        let bytes = match axum::body::to_bytes(body, 1048576).await {
            Ok(b) => b,
            Err(_) => {
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/json; charset=utf-8",
                    )
                    .body(Body::from(r#"{"code":400,"message":"请求体过大或无效"}"#))
                    .unwrap();
            }
        };

        let body_str = match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/json; charset=utf-8",
                    )
                    .body(Body::from(r#"{"code":400,"message":"请求体编码无效"}"#))
                    .unwrap();
            }
        };

        let cleaned = match sanitize_json_body(&body_str) {
            Ok(c) => c,
            Err(_) => body_str,
        };

        let request = Request::from_parts(parts, Body::from(cleaned));
        next.run(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape_basic() {
        let result = html_escape("<script>alert('xss')</script>");
        assert!(result.contains("&lt;"));
        assert!(!result.contains("<script>"));
    }

    #[test]
    fn test_sanitize_plain_text() {
        let result = sanitize_plain_text("<p>Hello <script>alert('xss')</script></p>");
        assert!(!result.contains("<script>"));
        assert!(!result.contains("<p>"));
    }

    #[test]
    fn test_sanitize_rich_text_safe() {
        let result = sanitize_rich_text("<p>Hello <strong>world</strong></p>");
        assert!(result.contains("<p>"));
        assert!(result.contains("<strong>"));
    }

    #[test]
    fn test_sanitize_rich_text_dangerous() {
        let result = sanitize_rich_text("<script>alert('xss')</script><p>safe</p>");
        assert!(!result.contains("<script>"));
        assert!(result.contains("<p>safe</p>"));
    }

    #[test]
    fn test_sanitize_rich_text_remove_style() {
        let result = sanitize_rich_text(r#"<p style="color:red">text</p>"#);
        assert!(!result.contains("style"));
        assert!(result.contains("text"));
    }

    #[test]
    fn test_sanitize_rich_text_remove_onclick() {
        let result = sanitize_rich_text(r#"<a onclick="alert(1)">link</a>"#);
        assert!(!result.contains("onclick"));
    }

    #[test]
    fn test_sanitize_rich_text_empty() {
        let result = sanitize_rich_text("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_sanitize_json_body() {
        let json = r#"{"name": "John", "bio": "<script>alert(1)</script>"}"#;
        let result = sanitize_json_body(json).unwrap();
        assert!(result.contains("John"));
        assert!(!result.contains("<script>"));
    }

    #[test]
    fn test_sanitize_json_body_invalid_json() {
        let result = sanitize_json_body("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_and_sanitize_plain() {
        let result = html_escape("hello < world");
        assert!(result.contains("&lt;"));
    }

    #[test]
    fn test_sanitize_json_nested() {
        let json = r#"{"users":[{"name":"<script>x</script>"}],"meta":{"desc":"<p>hi</p>"}}"#;
        let result = sanitize_json_body(json).unwrap();
        assert!(!result.contains("<script>"));
    }
}