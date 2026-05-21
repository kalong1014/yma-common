//! yma-auth::auth_service — 认证服务编排
//!
//! 提供统一的用户/角色/权限管理入口

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;
use uuid::Uuid;

use crate::jwt::JwtService;
use crate::permission::{Permission, PermissionStore};
use crate::role::{RoleDefinition, RoleStore};
use crate::user::{User, UserStore};

/// 认证错误
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("用户不存在")]
    UserNotFound,
    #[error("密码错误")]
    InvalidPassword,
    #[error("用户已禁用")]
    UserDisabled,
    #[error("无效的token")]
    InvalidToken,
    #[error("权限不足")]
    InsufficientPermission,
    #[error("内部错误: {0}")]
    InternalError(String),
}

/// 认证服务
pub struct AuthService {
    user_store: Arc<RwLock<UserStore>>,
    role_store: Arc<RwLock<RoleStore>>,
    permission_store: Arc<RwLock<PermissionStore>>,
    jwt_service: JwtService,
}

impl AuthService {
    /// 创建认证服务（自动初始化各存储）
    pub fn new(jwt_secret: String, access_ttl_minutes: i64, refresh_ttl_days: i64) -> Self {
        Self {
            user_store: Arc::new(RwLock::new(UserStore::new())),
            role_store: Arc::new(RwLock::new(RoleStore::new())),
            permission_store: Arc::new(RwLock::new(PermissionStore::new())),
            jwt_service: JwtService::new(jwt_secret.as_bytes()).with_ttl(access_ttl_minutes, refresh_ttl_days),
        }
    }

    // ---------- 认证流程 ----------

    /// 用户登录 -> 返回 JWT Token 字符串
    pub fn login(&self, username: &str, password: &str) -> Result<String, AuthError> {
        let store = self.user_store.read();
        let user = store
            .get_user_by_username(username)
            .ok_or(AuthError::UserNotFound)?
            .clone();

        if !user.is_active {
            return Err(AuthError::UserDisabled);
        }

        if !user.verify_password(password) {
            return Err(AuthError::InvalidPassword);
        }

        drop(store);

        // 更新最后登录时间
        let mut store = self.user_store.write();
        if let Some(db_user) = store.get_user_by_username(username) {
            let mut db_user = db_user.clone();
            db_user.update_last_login();
            store.update_user(db_user);
        }
        drop(store);

        // 签发 JWT
        let token = self
            .jwt_service
            .generate_token(user.id, &user.username, &user.role, vec![])
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        Ok(token)
    }

    /// 验证 Token -> 返回 (user_id, username)
    pub fn verify_token(&self, token: &str) -> Result<(Uuid, String), AuthError> {
        let claims = self
            .jwt_service
            .verify_token(token)
            .map_err(|_| AuthError::InvalidToken)?;

        let user_id = Uuid::parse_str(&claims.sub).map_err(|e| AuthError::InternalError(e.to_string()))?;
        Ok((user_id, claims.username))
    }

    /// 检查用户权限
    pub fn check_permission(&self, user_id: &Uuid, permission_code: &str) -> Result<bool, AuthError> {
        let store = self.user_store.read();
        let user = store
            .get_user_by_id(user_id)
            .ok_or(AuthError::UserNotFound)?;

        let role_code = user.role.clone();
        drop(store);

        let role_store = self.role_store.read();
        let role = role_store
            .get_role_by_code(&role_code)
            .ok_or_else(|| AuthError::InternalError("Role not found".to_string()))?;

        let perm_store = self.permission_store.read();
        let permission = perm_store.get_permission_by_code(permission_code);

        let has_perm = match permission {
            Some(perm) => role.has_permission_recursive(&perm.id, &role_store),
            None => false,
        };

        Ok(has_perm)
    }

    // ---------- 用户管理 ----------

    /// 添加用户 -> 返回 user_id
    pub fn add_user(
        &self,
        username: String,
        email: String,
        password: String,
    ) -> Result<Uuid, AuthError> {
        let user = User::new(username, email, password)
            .map_err(|e| AuthError::InternalError(e))?;
        let id = user.id;
        let mut store = self.user_store.write();
        store.add_user(user);
        Ok(id)
    }

    /// 获取用户信息
    pub fn get_user_info(&self, user_id: &Uuid) -> Result<User, AuthError> {
        let store = self.user_store.read();
        store
            .get_user_by_id(user_id)
            .cloned()
            .ok_or(AuthError::UserNotFound)
    }

    // ---------- 角色管理 ----------

    /// 添加角色 -> 返回 role_id
    pub fn add_role(
        &self,
        name: String,
        description: String,
        code: String,
        level: i32,
    ) -> Result<Uuid, AuthError> {
        let role = RoleDefinition::new(name, description, code, level);
        let id = role.id;
        let mut store = self.role_store.write();
        store.add_role(role);
        Ok(id)
    }

    /// 获取角色信息
    pub fn get_role_info(&self, role_id: &Uuid) -> Result<RoleDefinition, AuthError> {
        let store = self.role_store.read();
        store
            .get_role_by_id(role_id)
            .cloned()
            .ok_or(AuthError::InternalError("Role not found".to_string()))
    }

    /// 给角色添加权限
    pub fn add_permission_to_role(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), AuthError> {
        let mut store = self.role_store.write();
        let mut role = store
            .get_role_by_id(role_id)
            .cloned()
            .ok_or_else(|| AuthError::InternalError("Role not found".to_string()))?;
        role.add_permission(*permission_id);
        store.update_role(role);
        Ok(())
    }

    /// 给用户添加角色
    pub fn add_role_to_user(&self, user_id: &Uuid, role_id: &Uuid) -> Result<(), AuthError> {
        let role_store = self.role_store.read();
        let role = role_store
            .get_role_by_id(role_id)
            .ok_or_else(|| AuthError::InternalError("Role not found".to_string()))?;
        let role_code = role.code.clone();
        drop(role_store);

        let mut store = self.user_store.write();
        let mut user = store
            .get_user_by_id(user_id)
            .cloned()
            .ok_or(AuthError::UserNotFound)?;
        user.set_role(role_code);
        store.update_user(user);
        Ok(())
    }

    // ---------- 权限管理 ----------

    /// 添加权限 -> 返回 permission_id
    pub fn add_permission(
        &self,
        name: String,
        description: String,
        code: String,
    ) -> Result<Uuid, AuthError> {
        let permission = Permission::new(name, description, code);
        let id = permission.id;
        let mut store = self.permission_store.write();
        store.add_permission(permission);
        Ok(id)
    }

    /// 获取权限信息
    pub fn get_permission_info(&self, permission_id: &Uuid) -> Result<Permission, AuthError> {
        let store = self.permission_store.read();
        store
            .get_permission_by_id(permission_id)
            .cloned()
            .ok_or_else(|| AuthError::InternalError("Permission not found".to_string()))
    }

    // ---------- 存储访问器 ----------

    pub fn user_store(&self) -> Arc<RwLock<UserStore>> {
        self.user_store.clone()
    }

    pub fn role_store(&self) -> Arc<RwLock<RoleStore>> {
        self.role_store.clone()
    }

    pub fn permission_store(&self) -> Arc<RwLock<PermissionStore>> {
        self.permission_store.clone()
    }

    pub fn jwt_service(&self) -> &JwtService {
        &self.jwt_service
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_service_new() {
        let service = AuthService::new("test_secret".to_string(), 15, 7);
        assert_eq!(service.user_store.read().get_all_users().len(), 0);
        assert_eq!(service.role_store.read().get_all_roles().len(), 10); // 系统角色
    }

    #[test]
    fn test_auth_service_user_crud() {
        let service = AuthService::new("test_secret".to_string(), 15, 7);

        let user_id = service
            .add_user("alice".to_string(), "alice@example.com".to_string(), "password123".to_string())
            .unwrap();

        let user = service.get_user_info(&user_id).unwrap();
        assert_eq!(user.username, "alice");

        let token = service.login("alice", "password123").unwrap();
        assert!(!token.is_empty());

        let (uid, username) = service.verify_token(&token).unwrap();
        assert_eq!(uid, user_id);
        assert_eq!(username, "alice");
    }

    #[test]
    fn test_auth_service_permission() {
        let service = AuthService::new("test_secret".to_string(), 15, 7);

        let perm_id = service
            .add_permission("测试权限".to_string(), "测试".to_string(), "test:perm".to_string())
            .unwrap();

        let role_id = service
            .add_role("测试角色".to_string(), "测试".to_string(), "test_role".to_string(), 5)
            .unwrap();

        service.add_permission_to_role(&role_id, &perm_id).unwrap();

        let role = service.get_role_info(&role_id).unwrap();
        assert!(role.has_permission(&perm_id));
    }
}