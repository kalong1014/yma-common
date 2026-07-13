#![deny(missing_docs)]
//! 统一API响应格式模块，提供标准化的API响应结构体。
//!
//! # Features
//! - `web`: 启用axum集成，实现`IntoResponse` trait

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// 统一API响应结构体。
///
/// 泛型参数 `T` 表示响应数据载荷的类型。
#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse<T: Serialize + Clone + Send + Sync + 'static> {
    /// HTTP状态码或业务错误码，成功时为200
    pub code: i32,
    /// 人类可读的消息描述
    pub message: String,
    /// 响应数据载荷
    pub data: Option<T>,
    /// Unix毫秒级时间戳
    pub timestamp: i64,
    /// 请求追踪ID（UUID v4格式）
    pub request_id: String,
}

impl<T: Serialize + Clone + Send + Sync + 'static> ApiResponse<T> {
    /// 创建成功响应。
    ///
    /// # 参数
    /// * `data` - 响应数据载荷
    ///
    /// # 返回值
    /// code为200、message为"success"的ApiResponse实例。
    pub fn success(data: T) -> Self {
        Self {
            code: 200,
            message: "success".to_string(),
            data: Some(data),
            timestamp: Utc::now().timestamp_millis(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// 创建错误响应（无数据载荷）。
    ///
    /// # 参数
    /// * `code` - 错误码，不能为200（传入200会自动替换为500）
    /// * `message` - 错误消息
    ///
    /// # 返回值
    /// 对应的ApiResponse实例，data为None。
    pub fn error(code: i32, message: String) -> Self {
        let code = if code == 200 { 500 } else { code };
        Self {
            code,
            message,
            data: None,
            timestamp: Utc::now().timestamp_millis(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// 创建错误响应（附带数据载荷）。
    ///
    /// # 参数
    /// * `code` - 错误码
    /// * `message` - 错误消息
    /// * `data` - 附带的数据载荷（如验证失败时的字段错误信息）
    ///
    /// # 返回值
    /// 对应的ApiResponse实例。
    pub fn error_with_data(code: i32, message: String, data: T) -> Self {
        let code = if code == 200 { 500 } else { code };
        Self {
            code,
            message,
            data: Some(data),
            timestamp: Utc::now().timestamp_millis(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[cfg(feature = "web")]
impl<T: Serialize + Clone + Send + Sync + 'static> axum::response::IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string());
        let status_code = match self.code {
            200 => axum::http::StatusCode::OK,
            400 => axum::http::StatusCode::BAD_REQUEST,
            401 => axum::http::StatusCode::UNAUTHORIZED,
            403 => axum::http::StatusCode::FORBIDDEN,
            404 => axum::http::StatusCode::NOT_FOUND,
            409 => axum::http::StatusCode::CONFLICT,
            422 => axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            429 => axum::http::StatusCode::TOO_MANY_REQUESTS,
            500 => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            503 => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };
        let mut response = axum::response::Response::new(axum::body::Body::from(body));
        *response.status_mut() = status_code;
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json; charset=utf-8"),
        );
        response
    }
}

/// 分页响应结构体。
///
/// 泛型参数 `T` 表示列表项的类型。
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedApiResponse<T: Serialize + Clone + Send + Sync + 'static> {
    /// HTTP状态码
    pub code: i32,
    /// 消息描述
    pub message: String,
    /// 当前页的数据列表
    pub data: Vec<T>,
    /// 分页元信息
    pub pagination: PaginationInfo,
    /// Unix毫秒级时间戳
    pub timestamp: i64,
    /// 请求追踪ID
    pub request_id: String,
}

impl<T: Serialize + Clone + Send + Sync + 'static> PaginatedApiResponse<T> {
    /// 创建分页成功响应。
    ///
    /// # 参数
    /// * `data` - 当前页的数据列表
    /// * `pagination` - 分页元信息
    ///
    /// # 返回值
    /// code为200的分页响应实例。
    pub fn success(data: Vec<T>, pagination: PaginationInfo) -> Self {
        Self {
            code: 200,
            message: "success".to_string(),
            data,
            pagination,
            timestamp: Utc::now().timestamp_millis(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// 分页元信息结构体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    /// 当前页码，最小值为1
    pub page: u64,
    /// 每页记录数，最小1最大100
    pub page_size: u64,
    /// 总记录数
    pub total: u64,
    /// 总页数
    pub total_pages: u64,
}

/// 业务错误码枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 200 - 操作成功
    Success,
    /// 400 - 请求参数错误
    BadRequest,
    /// 401 - 未授权
    Unauthorized,
    /// 403 - 禁止访问
    Forbidden,
    /// 404 - 资源不存在
    NotFound,
    /// 409 - 资源冲突
    Conflict,
    /// 422 - 数据验证失败
    ValidationError,
    /// 429 - 请求过于频繁
    TooManyRequests,
    /// 500 - 服务器内部错误
    InternalError,
    /// 503 - 服务不可用
    ServiceUnavailable,
}

impl ErrorCode {
    /// 获取错误码对应的HTTP状态码和默认消息。
    ///
    /// # 返回值
    /// (状态码, 默认中文消息) 元组。
    pub fn to_http_status(&self) -> (i32, String) {
        match self {
            ErrorCode::Success => (200, "操作成功".to_string()),
            ErrorCode::BadRequest => (400, "请求参数错误".to_string()),
            ErrorCode::Unauthorized => (401, "未授权访问，请先登录".to_string()),
            ErrorCode::Forbidden => (403, "禁止访问，权限不足".to_string()),
            ErrorCode::NotFound => (404, "请求的资源不存在".to_string()),
            ErrorCode::Conflict => (409, "资源冲突，数据已存在".to_string()),
            ErrorCode::ValidationError => (422, "数据验证失败，请检查输入".to_string()),
            ErrorCode::TooManyRequests => (429, "请求过于频繁，请稍后重试".to_string()),
            ErrorCode::InternalError => (500, "服务器内部错误，请联系管理员".to_string()),
            ErrorCode::ServiceUnavailable => (503, "服务暂时不可用，请稍后重试".to_string()),
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (code, _msg) = self.to_http_status();
        serializer.serialize_i32(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_response() {
        let resp = ApiResponse::success(42);
        assert_eq!(resp.code, 200);
        assert_eq!(resp.message, "success");
        assert_eq!(resp.data, Some(42));
        assert!(resp.timestamp > 0);
        assert!(!resp.request_id.is_empty());
    }

    #[test]
    fn test_error_response() {
        let resp = ApiResponse::<()>::error(400, "参数错误".to_string());
        assert_eq!(resp.code, 400);
        assert_eq!(resp.message, "参数错误");
        assert_eq!(resp.data, None);
    }

    #[test]
    fn test_error_code_200_replaced() {
        let resp = ApiResponse::<()>::error(200, "bad".to_string());
        assert_eq!(resp.code, 500);
    }

    #[test]
    fn test_error_with_data() {
        let resp = ApiResponse::error_with_data(422, "验证失败".to_string(), vec!["field1"]);
        assert_eq!(resp.code, 422);
        assert_eq!(resp.data, Some(vec!["field1"]));
    }

    #[test]
    fn test_paginated_response() {
        let info = PaginationInfo {
            page: 1,
            page_size: 20,
            total: 100,
            total_pages: 5,
        };
        let resp = PaginatedApiResponse::success(vec![1, 2, 3], info.clone());
        assert_eq!(resp.code, 200);
        assert_eq!(resp.data.len(), 3);
        assert_eq!(resp.pagination.total, 100);
    }

    #[test]
    fn test_error_code_to_http_status() {
        assert_eq!(ErrorCode::Success.to_http_status().0, 200);
        assert_eq!(ErrorCode::BadRequest.to_http_status().0, 400);
        assert_eq!(ErrorCode::NotFound.to_http_status().0, 404);
    }

    #[test]
    fn test_error_code_serialize() {
        let json = serde_json::to_string(&ErrorCode::BadRequest).unwrap();
        assert_eq!(json, "400");
    }

    #[test]
    fn test_pagination_info_deserialize() {
        let json = r#"{"page":1,"page_size":20,"total":100,"total_pages":5}"#;
        let info: PaginationInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.page, 1);
        assert_eq!(info.total_pages, 5);
    }
}