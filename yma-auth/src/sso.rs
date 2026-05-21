//! yma-auth::sso — 单点登录 (SSO) 模块
//!
//! 提供 OAuth2/OIDC 风格的 SSO 认证支持

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SSO 提供者配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProvider {
    pub id: Uuid,
    pub name: String,
    pub provider_type: SsoProviderType,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

/// SSO 提供者类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SsoProviderType {
    OAuth2,
    OpenIdConnect,
    SAML,
    Custom(String),
}

/// SSO 认证状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoState {
    pub state_token: String,
    pub provider_id: Uuid,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// SSO Token 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
}

/// SSO 用户信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUserInfo {
    pub provider_id: Uuid,
    pub external_id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub raw_data: serde_json::Value,
}

/// SSO 管理器
#[derive(Debug, Default)]
pub struct SsoManager {
    providers: Vec<SsoProvider>,
    states: Vec<SsoState>,
}

impl SsoManager {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            states: Vec::new(),
        }
    }

    /// 注册 SSO 提供者
    pub fn register_provider(&mut self, provider: SsoProvider) {
        self.providers.push(provider);
    }

    /// 获取所有启用的提供者
    pub fn get_enabled_providers(&self) -> Vec<&SsoProvider> {
        self.providers.iter().filter(|p| p.enabled).collect()
    }

    /// 通过 ID 获取提供者
    pub fn get_provider(&self, id: &Uuid) -> Option<&SsoProvider> {
        self.providers.iter().find(|p| p.id == *id)
    }

    /// 生成授权 URL
    pub fn generate_auth_url(&mut self, provider_id: &Uuid, redirect_uri: &str) -> Option<String> {
        let provider = self.get_provider(provider_id)?.clone();
        if !provider.enabled {
            return None;
        }

        let state_token = Uuid::new_v4().to_string();
        let scopes = provider.scopes.join(" ");
        let authorization_url = provider.authorization_url.clone();
        let client_id = provider.client_id.clone();
        let state = SsoState {
            state_token: state_token.clone(),
            provider_id: *provider_id,
            redirect_uri: redirect_uri.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        };
        self.states.push(state);

        let url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            authorization_url,
            client_id,
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&scopes),
            state_token
        );

        Some(url)
    }

    /// 验证 state token
    pub fn validate_state(&mut self, state_token: &str) -> Option<SsoState> {
        let now = Utc::now();
        if let Some(pos) = self.states.iter().position(|s| s.state_token == state_token) {
            let state = self.states.remove(pos);
            if now <= state.expires_at {
                return Some(state);
            }
        }
        None
    }

    /// 清理过期 state
    pub fn cleanup_expired_states(&mut self) -> usize {
        let now = Utc::now();
        let before = self.states.len();
        self.states.retain(|s| now <= s.expires_at);
        before - self.states.len()
    }

    /// 移除提供者
    pub fn remove_provider(&mut self, id: &Uuid) -> bool {
        if let Some(pos) = self.providers.iter().position(|p| p.id == *id) {
            self.providers.remove(pos);
            true
        } else {
            false
        }
    }

    /// 获取提供者数量
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

/// SSO 登录结果
#[derive(Debug, Clone)]
pub enum SsoLoginResult {
    Success {
        user_info: SsoUserInfo,
        token: String,
    },
    Failed {
        error: String,
    },
    NeedLinkAccount {
        user_info: SsoUserInfo,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_provider() -> SsoProvider {
        SsoProvider {
            id: Uuid::new_v4(),
            name: "Google".to_string(),
            provider_type: SsoProviderType::OAuth2,
            client_id: "test_client_id".to_string(),
            client_secret: "test_secret".to_string(),
            authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
            redirect_uri: "http://localhost:8080/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            enabled: true,
        }
    }

    #[test]
    fn test_register_provider() {
        let mut manager = SsoManager::new();
        let provider = create_test_provider();
        let id = provider.id;

        manager.register_provider(provider);
        assert_eq!(manager.provider_count(), 1);
        assert!(manager.get_provider(&id).is_some());
    }

    #[test]
    fn test_generate_auth_url() {
        let mut manager = SsoManager::new();
        let provider = create_test_provider();
        let id = provider.id;
        manager.register_provider(provider);

        let url = manager.generate_auth_url(&id, "http://localhost/callback");
        assert!(url.is_some());
        let url = url.unwrap();
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("client_id=test_client_id"));
    }

    #[test]
    fn test_validate_state() {
        let mut manager = SsoManager::new();
        let provider = create_test_provider();
        let id = provider.id;
        manager.register_provider(provider);

        let url = manager.generate_auth_url(&id, "http://localhost/callback").unwrap();
        let state = url.split("state=").nth(1).unwrap().to_string();

        let validated = manager.validate_state(&state);
        assert!(validated.is_some());

        // 第二次验证应该失败（state 已被消费）
        let validated2 = manager.validate_state(&state);
        assert!(validated2.is_none());
    }

    #[test]
    fn test_cleanup_expired_states() {
        let mut manager = SsoManager::new();
        let provider = create_test_provider();
        manager.register_provider(provider);

        manager.generate_auth_url(&provider.id, "http://localhost/callback");
        assert_eq!(manager.states.len(), 1);

        // 手动设置过期
        manager.states[0].expires_at = Utc::now() - chrono::Duration::minutes(1);

        let cleaned = manager.cleanup_expired_states();
        assert_eq!(cleaned, 1);
        assert!(manager.states.is_empty());
    }

    #[test]
    fn test_disabled_provider() {
        let mut manager = SsoManager::new();
        let mut provider = create_test_provider();
        provider.enabled = false;
        let id = provider.id;
        manager.register_provider(provider);

        let url = manager.generate_auth_url(&id, "http://localhost/callback");
        assert!(url.is_none());
    }
}