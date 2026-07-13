#![deny(missing_docs)]
//! SQL注入防护模块，基于正则规则检测常见SQL注入模式。
//!
//! 规则覆盖: UNION SELECT注入、注释注入、时间盲注、恒真条件绕过。

use axum::body::Body;
use regex::Regex;
use std::sync::LazyLock;

static SQLI_RULES: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "SQLI_UNION_SELECT",
            Regex::new(r"(?i)\bUNION\s+SELECT\b").unwrap(),
        ),
        (
            "SQLI_COMMENT",
            Regex::new(r"--\s*$|--\s*\w|#\s*$|#\s*\w|/\*.*\*/").unwrap(),
        ),
        (
            "SQLI_BLIND",
            Regex::new(r"(?i)\bSLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+\s*,|WAITFOR\s+DELAY\s+|pg_sleep\s*\(\s*\d+").unwrap(),
        ),
        (
            "SQLI_LOGIC_BYPASS",
            Regex::new(r#"(?i)\bOR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?|\bAND\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?"#).unwrap(),
        ),
    ]
});

/// 检查单个字符串是否包含SQL注入特征。
///
/// # 参数
/// * `input` - 待检测的输入字符串
///
/// # 返回值
/// Ok(()) 表示未检测到注入，Err(&str) 返回匹配到的规则名称。
pub fn check_sql_injection(input: &str) -> Result<(), &'static str> {
    if input.len() < 4 || input.len() > 10000 {
        return Ok(());
    }

    for (rule_name, regex) in SQLI_RULES.iter() {
        if regex.is_match(input) {
            return Err(rule_name);
        }
    }

    Ok(())
}

fn extract_strings_from_json(value: &serde_json::Value) -> Vec<String> {
    let mut result = Vec::new();

    match value {
        serde_json::Value::String(s) => {
            result.push(s.clone());
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                result.extend(extract_strings_from_json(item));
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                result.extend(extract_strings_from_json(v));
            }
        }
        _ => {}
    }

    result
}

fn check_sql_injection_in_json(body: &str) -> Result<(), &'static str> {
    let value = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let strings = extract_strings_from_json(&value);
    for s in &strings {
        check_sql_injection(s)?;
    }

    Ok(())
}

/// SQL注入防护Axum中间件。
///
/// # 返回值
/// axum middleware函数，检测POST/PUT/PATCH请求体的JSON内容中是否含SQL注入。
pub fn sql_injection_middleware() -> impl (
    Fn(axum::extract::Request, axum::middleware::Next) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = axum::response::Response> + Send>,
    >
) + Clone
       + Send
       + Sync
       + 'static {
    use axum::response::Response;

    |request: axum::extract::Request, next: axum::middleware::Next| {
        Box::pin(async move {
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
                        .body(Body::from(
                            r#"{"error":"Bad Request","message":"请求体过大或无效"}"#,
                        ))
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
                        .body(Body::from(
                            r#"{"error":"Bad Request","message":"请求体编码无效"}"#,
                        ))
                        .unwrap();
                }
            };

            if let Err(rule_name) = check_sql_injection_in_json(&body_str) {
                let body = serde_json::json!({
                    "error": "POTENTIAL_SQL_INJECTION",
                    "message": "检测到潜在的SQL注入攻击",
                    "rule": rule_name,
                })
                .to_string();
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/json; charset=utf-8",
                    )
                    .body(Body::from(body))
                    .unwrap();
            }

            let request = axum::http::Request::from_parts(parts, Body::from(body_str));
            next.run(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_union_select() {
        assert!(check_sql_injection("SELECT * FROM users UNION SELECT * FROM admins").is_err());
    }

    #[test]
    fn test_check_comment_injection() {
        assert!(check_sql_injection("' OR '1'='1' --").is_err());
        assert!(check_sql_injection("admin'#").is_err());
    }

    #[test]
    fn test_check_blind_injection() {
        assert!(check_sql_injection("SLEEP(5)").is_err());
        assert!(check_sql_injection("BENCHMARK(1000000,MD5('a'))").is_err());
        assert!(check_sql_injection("pg_sleep(10)").is_err());
    }

    #[test]
    fn test_check_logic_bypass() {
        assert!(check_sql_injection("OR 1=1").is_err());
        assert!(check_sql_injection("OR '1'='1'").is_err());
    }

    #[test]
    fn test_check_clean_input() {
        assert!(check_sql_injection("John Doe").is_ok());
        assert!(check_sql_injection("test@example.com").is_ok());
    }

    #[test]
    fn test_check_short_input() {
        assert!(check_sql_injection("ab").is_ok());
        assert!(check_sql_injection("abc").is_ok());
    }

    #[test]
    fn test_check_empty() {
        assert!(check_sql_injection("").is_ok());
    }

    #[test]
    fn test_check_legitimate_sql_syntax() {
        assert!(check_sql_injection("SELECT name FROM users").is_ok());
        assert!(check_sql_injection("INSERT INTO table VALUES (1)").is_ok());
    }
}