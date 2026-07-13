//! yma-auth::routes — 认证 API 路由
//!
//! 提供 Axum 认证相关路由和 Handler
//! 需要启用 `web` feature

use std::sync::Arc;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::jwt::JwtService;
use crate::user::UserStore;

// ============ 请求/响应 DTOs ============

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub token_type: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub tenant_id: Uuid,
    pub permissions: Vec<String>,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub name: String,
    pub tenant_id: Uuid,
    pub permissions: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeysListResponse {
    pub keys: Vec<ApiKeyItem>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyItem {
    pub key_prefix: String,
    pub name: String,
    pub tenant_id: Uuid,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub created_at: String,
}

// ============ 路由状态 ============

#[derive(Clone)]
pub struct AuthRoutesState {
    pub jwt_service: Arc<JwtService>,
    pub user_store: Arc<RwLock<UserStore>>,
}

impl AuthRoutesState {
    pub fn new(jwt_service: JwtService) -> Self {
        Self {
            jwt_service: Arc::new(jwt_service),
            user_store: Arc::new(RwLock::new(UserStore::new())),
        }
    }
}

// ============ 路由构建函数 ============

/// 构建认证相关路由
/// 路径: /api/v1/auth/login (POST), /api/v1/auth/refresh (POST)
pub fn auth_routes(state: AuthRoutesState) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/refresh", post(refresh_handler))
        .with_state(state)
}

// ============ Handler 函数 ============

/// 登录 Handler
pub async fn login_handler(
    State(state): State<AuthRoutesState>,
    Json(req): Json<LoginRequest>,
) -> Response {
    // 查找用户
    let store = state.user_store.read();
    let user = match store.get_user_by_username(&req.username) {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            )
                .into_response();
        }
    };
    drop(store);

    // 验证密码
    if !user.verify_password(&req.password) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        )
            .into_response();
    }

    // 签发 Token
    match state.jwt_service.issue(
        &user.id.to_string(),
        &user.username,
        &user.role,
        &[], // 简化处理，实际应从权限存储获取
    ) {
        Ok(token_pair) => {
            let response = LoginResponse {
                token: token_pair.access_token,
                token_type: "Bearer".to_string(),
                refresh_token: token_pair.refresh_token,
                expires_in: state.jwt_service.access_token_ttl_seconds(),
                user_id: user.id,
                username: user.username.clone(),
                role: user.role.clone(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// 刷新 Token Handler
pub async fn refresh_handler(
    State(state): State<AuthRoutesState>,
    Json(req): Json<RefreshRequest>,
) -> Response {
    match state.jwt_service.refresh(&req.refresh_token) {
        Ok(token_pair) => {
            let response = RefreshResponse {
                token: token_pair.access_token,
                expires_in: state.jwt_service.access_token_ttl_seconds(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"this_is_a_very_long_test_secret_for_jwt_service_32_bytes";

    #[test]
    fn test_auth_routes_state() {
        let jwt = JwtService::new(TEST_SECRET).unwrap();
        let state = AuthRoutesState::new(jwt);
        assert_eq!(state.user_store.read().get_all_users().len(), 0);
    }

    #[test]
    fn test_login_response_has_token_type_bearer() {
        let response = LoginResponse {
            token: "access_token".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: "refresh_token".to_string(),
            expires_in: 86400,
            user_id: Uuid::new_v4(),
            username: "test".to_string(),
            role: "user".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["token_type"], "Bearer");
    }
}