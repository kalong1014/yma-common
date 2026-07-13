use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// JWT 错误
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT Secret 长度必须至少 32 字节")]
    InvalidSecretLength,
    #[error("JWT 编码失败: {0}")]
    EncodeFailed(String),
    #[error("JWT 验证失败: {0}")]
    VerifyFailed(String),
    #[error("Token 已过期")]
    Expired,
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub permissions: Vec<String>,
}

/// JWT Token 响应
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// JWT 服务
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_ttl_minutes: i64,
    refresh_token_ttl_days: i64,
}

impl JwtService {
    pub fn new(secret: &[u8]) -> Result<Self, JwtError> {
        if secret.len() < 32 {
            return Err(JwtError::InvalidSecretLength);
        }
        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            access_token_ttl_minutes: 1440,
            refresh_token_ttl_days: 7,
        })
    }

    pub fn with_ttl(mut self, access_minutes: i64, refresh_days: i64) -> Self {
        self.access_token_ttl_minutes = access_minutes;
        self.refresh_token_ttl_days = refresh_days;
        self
    }

    /// 签发 Token
    pub fn issue(&self, sub: &str, username: &str, role: &str, permissions: &[String]) -> Result<TokenPair, JwtError> {
        let now = Utc::now();

        let access_claims = Claims {
            sub: sub.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(self.access_token_ttl_minutes)).timestamp(),
            jti: Uuid::new_v4().to_string(),
            permissions: permissions.to_vec(),
        };

        let refresh_claims = Claims {
            sub: sub.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::days(self.refresh_token_ttl_days)).timestamp(),
            jti: Uuid::new_v4().to_string(),
            permissions: vec![],
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodeFailed(e.to_string()))?;
        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodeFailed(e.to_string()))?;

        Ok(TokenPair { access_token, refresh_token })
    }

    /// 验证 Token
    pub fn verify(&self, token: &str) -> Result<Claims, JwtError> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| JwtError::VerifyFailed(e.to_string()))?;

        if token_data.claims.exp < Utc::now().timestamp() {
            return Err(JwtError::Expired);
        }

        Ok(token_data.claims)
    }

    /// 刷新 Token
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenPair, JwtError> {
        let claims = self.verify(refresh_token)?;
        self.issue(&claims.sub, &claims.username, &claims.role, &claims.permissions)
    }

    /// 生成 Token (便捷方法，返回 access_token 字符串)
    pub fn generate_token(
        &self,
        user_id: Uuid,
        username: &str,
        role: &str,
        permissions: Vec<String>,
    ) -> Result<String, JwtError> {
        let pair = self.issue(&user_id.to_string(), username, role, &permissions)?;
        Ok(pair.access_token)
    }

    /// 验证 Token (便捷方法)
    pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.verify(token)
    }

    /// 从 Token 提取用户信息 (user_id, username)
    pub fn extract_user_info(&self, token: &str) -> Option<(Uuid, String)> {
        let claims = self.verify(token).ok()?;
        let user_id = Uuid::parse_str(&claims.sub).ok()?;
        Some((user_id, claims.username))
    }

    /// 获取 access token 过期时间 (秒)
    pub fn access_token_ttl_seconds(&self) -> u64 {
        (self.access_token_ttl_minutes * 60) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"this_is_a_very_long_test_secret_for_jwt_service_32_bytes";

    #[test]
    fn test_jwt_issue_verify() {
        let service = JwtService::new(TEST_SECRET).unwrap();
        let token = service.issue("user1", "testuser", "admin", &["read".to_string()]).unwrap();
        let claims = service.verify(&token.access_token).unwrap();
        assert_eq!(claims.sub, "user1");
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn test_jwt_invalid_token() {
        let service = JwtService::new(TEST_SECRET).unwrap();
        let result = service.verify("invalid_token");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_refresh() {
        let service = JwtService::new(TEST_SECRET).unwrap();
        let token = service.issue("user1", "testuser", "admin", &[]).unwrap();
        let refreshed = service.refresh(&token.refresh_token).unwrap();
        assert_ne!(refreshed.access_token, token.access_token);
    }

    #[test]
    fn test_jwt_expired_token() {
        let service = JwtService::with_ttl(JwtService::new(TEST_SECRET).unwrap(), -1, 7);
        let token = service.issue("user1", "test", "user", &[]).unwrap();
        let result = service.verify(&token.access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_default_ttl_is_24_hours() {
        let service = JwtService::new(TEST_SECRET).unwrap();
        assert_eq!(service.access_token_ttl_seconds(), 86400);
    }

    #[test]
    fn test_jwt_secret_length_validation() {
        let result = JwtService::new(b"short_secret");
        assert!(matches!(result, Err(JwtError::InvalidSecretLength)));

        let valid_secret = b"01234567890123456789012345678901";
        assert_eq!(valid_secret.len(), 32);
        assert!(JwtService::new(valid_secret).is_ok());
    }
}