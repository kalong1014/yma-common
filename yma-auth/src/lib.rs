//! yma-auth 认证授权统一库
//!
//! 提供 JWT/RBAC/MFA/Password/User/Permission/Role 的标准化接口
//! 版本锁定: 0.3.0

pub mod jwt;
pub mod rbac;
pub mod password;
pub mod totp;
pub mod api_key;
pub mod api_key_store;
pub mod mfa;
pub mod session;
pub mod session_refresh;
pub mod brute_force;
pub mod challenge;
pub mod user;
pub mod permission;
pub mod role;
pub mod auth_service;
pub mod user_config;
pub mod sso;

#[cfg(feature = "web")]
pub mod middleware;
#[cfg(feature = "web")]
pub mod routes;

pub use jwt::JwtService;
pub use rbac::RbacEngine;
pub use password::{PasswordHasher, hash_password, verify_password};
pub use totp::TotpService;
pub use api_key::ApiKeyGenerator;
pub use api_key_store::{ApiKeyRecord, ApiKeyStore};
pub use mfa::MfaService;
pub use session::SessionStore;
pub use session_refresh::{RefreshTokenManager, RefreshTokenConfig, RefreshTokenRecord, RefreshTokenStatus};
pub use brute_force::BruteForceGuard;
pub use challenge::ChallengeManager;
pub use user::{User, UserProfile, UserStore};
pub use permission::{Permission, PermissionStore};
pub use role::{Role, RoleDefinition, RoleStore};
pub use auth_service::{AuthError, AuthService};
pub use user_config::UserConfigStore;
pub use sso::{SsoManager, SsoProvider, SsoProviderType, SsoUserInfo, SsoLoginResult};

#[cfg(feature = "web")]
pub use middleware::{AuthContext, AuthProvider, AuthenticatedUser, AuthErrorResponse, auth_middleware};
#[cfg(feature = "web")]
pub use routes::{AuthRoutesState, auth_routes, LoginRequest, LoginResponse, RefreshRequest, RefreshResponse};