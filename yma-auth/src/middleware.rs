//! yma-auth::middleware — 认证中间件
//!
//! 提供 Axum 认证中间件，支持 JWT 和 API Key 认证
//! 需要启用 `web` feature

use std::sync::Arc;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::jwt::{Claims, JwtService};

/// 认证提供者枚举
#[derive(Debug, Clone)]
pub enum AuthProvider {
    Jwt(Claims),
    ApiKey {
        key: String,
        tenant_id: Uuid,
        permissions: Vec<String>,
    },
}

impl AuthProvider {
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            AuthProvider::Jwt(claims) => Uuid::parse_str(&claims.sub).ok(),
            AuthProvider::ApiKey { tenant_id, .. } => Some(*tenant_id),
        }
    }

    pub fn permissions(&self) -> &[String] {
        match self {
            AuthProvider::Jwt(claims) => &claims.permissions,
            AuthProvider::ApiKey { permissions, .. } => permissions.as_slice(),
        }
    }

    pub fn is_jwt(&self) -> bool {
        matches!(self, AuthProvider::Jwt(_))
    }

    pub fn is_api_key(&self) -> bool {
        matches!(self, AuthProvider::ApiKey { .. })
    }
}

/// 已认证用户
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub role: String,
    pub permissions: Vec<String>,
    pub auth_provider: AuthProvider,
}

impl AuthenticatedUser {
    /// 从 JWT Claims 构造
    pub fn from_claims(claims: Claims) -> Self {
        let user_id = Uuid::parse_str(&claims.sub).unwrap_or_default();
        Self {
            user_id,
            role: claims.role.clone(),
            permissions: claims.permissions.clone(),
            auth_provider: AuthProvider::Jwt(claims),
        }
    }

    /// 从 API Key 构造
    pub fn from_api_key(key: &str, tenant_id: Uuid, permissions: &[String]) -> Self {
        Self {
            user_id: tenant_id,
            role: "api_key".to_string(),
            permissions: permissions.to_vec(),
            auth_provider: AuthProvider::ApiKey {
                key: key.to_string(),
                tenant_id,
                permissions: permissions.to_vec(),
            },
        }
    }

    /// 检查是否拥有指定权限（支持通配符 "*"）
    pub fn has_permission(&self, permission: &str) -> bool {
        if self.permissions.contains(&"*".to_string()) {
            return true;
        }
        self.permissions.contains(&permission.to_string())
    }

    /// 检查角色（admin 角色自动拥有所有权限）
    pub fn has_role(&self, role: &str) -> bool {
        self.role == role || self.role == "admin"
    }
}

/// 认证上下文
#[derive(Clone)]
pub struct AuthContext {
    jwt_service: Arc<JwtService>,
    public_paths: Vec<String>,
}

impl AuthContext {
    /// 创建认证上下文
    pub fn new(jwt_service: JwtService) -> Self {
        Self {
            jwt_service: Arc::new(jwt_service),
            public_paths: vec![
                "/api/v1/auth/login".to_string(),
                "/api/v1/auth/refresh".to_string(),
                "/health".to_string(),
            ],
        }
    }

    /// 配置公开路径（无需认证）
    pub fn with_public_paths(mut self, paths: Vec<String>) -> Self {
        self.public_paths.extend(paths);
        self
    }

    /// 判断是否为公开路径
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    /// 认证 JWT Token -> AuthenticatedUser
    pub async fn authenticate_jwt(&self, token: &str) -> Result<AuthenticatedUser, AuthErrorResponse> {
        let claims = self.jwt_service.verify(token)
            .map_err(|e| AuthErrorResponse::unauthorized(&format!("JWT verify failed: {}", e)))?;
        Ok(AuthenticatedUser::from_claims(claims))
    }

    /// 通用认证（优先 JWT）
    pub async fn authenticate(
        &self,
        jwt_token: Option<&str>,
    ) -> Result<AuthenticatedUser, AuthErrorResponse> {
        if let Some(token) = jwt_token {
            self.authenticate_jwt(token).await
        } else {
            Err(AuthErrorResponse::unauthorized("No authentication provided"))
        }
    }
}

/// 认证错误响应
#[derive(Debug, Clone, Serialize)]
pub struct AuthErrorResponse {
    pub code: u16,
    pub message: String,
    pub detail: String,
}

impl AuthErrorResponse {
    pub fn unauthorized(detail: &str) -> Self {
        Self {
            code: 401,
            message: "Unauthorized".to_string(),
            detail: detail.to_string(),
        }
    }

    pub fn forbidden(detail: &str) -> Self {
        Self {
            code: 403,
            message: "Forbidden".to_string(),
            detail: detail.to_string(),
        }
    }
}

impl IntoResponse for AuthErrorResponse {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "code": self.code,
            "message": self.message,
            "detail": self.detail,
        }));
        (StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body).into_response()
    }
}

/// Axum 认证中间件
/// 从 Authorization: Bearer {token} 头读取凭据
/// 将 AuthenticatedUser 注入到 request.extensions
pub async fn auth_middleware(
    State(auth_context): State<Arc<AuthContext>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // 公开路径跳过认证
    if auth_context.is_public_path(&path) {
        return next.run(request).await;
    }

    // 提取 JWT Token
    let jwt_token = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "));

    // 认证
    match auth_context.authenticate(jwt_token).await {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}

/// 从 request.extensions 提取 AuthenticatedUser
pub fn get_authenticated_user(request: &Request) -> Option<&AuthenticatedUser> {
    request.extensions().get::<AuthenticatedUser>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_provider() {
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            username: "test".to_string(),
            role: "admin".to_string(),
            iat: 0,
            exp: i64::MAX,
            jti: Uuid::new_v4().to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
        };

        let provider = AuthProvider::Jwt(claims);
        assert!(provider.is_jwt());
        assert!(!provider.is_api_key());
        assert!(provider.user_id().is_some());
    }

    #[test]
    fn test_authenticated_user_permissions() {
        let user = AuthenticatedUser::from_api_key(
            "key123",
            Uuid::new_v4(),
            &["read".to_string(), "write".to_string()],
        );

        assert!(user.has_permission("read"));
        assert!(!user.has_permission("delete"));
        assert!(user.has_role("api_key"));
    }

    #[test]
    fn test_auth_context_public_paths() {
        let jwt = JwtService::new(b"this_is_a_very_long_test_secret_for_jwt_service_32_bytes").unwrap();
        let ctx = AuthContext::new(jwt);

        assert!(ctx.is_public_path("/api/v1/auth/login"));
        assert!(ctx.is_public_path("/health"));
        assert!(!ctx.is_public_path("/api/v1/users"));
    }
}