//! yma-auth::user — 用户与用户存储
//!
//! 提供 User / UserProfile / UserStore 三个核心类型

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::password::PasswordHasher;

// ============ 用户资料 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
}

// ============ 用户 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub profile: Option<UserProfile>,
}

impl User {
    /// 创建新用户（密码自动 bcrypt 哈希）
    pub fn new(username: String, email: String, password: String) -> Result<Self, String> {
        let password_hash = PasswordHasher::hash(&password)
            .map_err(|e| format!("Password hash failed: {}", e))?;

        Ok(Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash: Some(password_hash),
            role: "user".to_string(),
            is_active: true,
            is_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            profile: None,
        })
    }

    /// 创建 SSO 用户（无本地密码）
    pub fn from_sso(username: String, email: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash: None,
            role: "user".to_string(),
            is_active: true,
            is_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            profile: None,
        }
    }

    /// 验证密码（内部调用 PasswordHasher::verify）
    pub fn verify_password(&self, password: &str) -> bool {
        match &self.password_hash {
            Some(hash) => PasswordHasher::verify(password, hash).unwrap_or(false),
            None => false,
        }
    }

    /// 设置新密码（自动 bcrypt 哈希）
    pub fn set_password(&mut self, password: String) -> Result<(), String> {
        self.password_hash = Some(
            PasswordHasher::hash(&password)
                .map_err(|e| format!("Password hash failed: {}", e))?,
        );
        self.updated_at = Utc::now();
        Ok(())
    }

    /// 更新最后登录时间
    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// 启用用户
    pub fn enable(&mut self) {
        self.is_active = true;
        self.updated_at = Utc::now();
    }

    /// 禁用用户
    pub fn disable(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }

    /// 验证用户邮箱
    pub fn verify(&mut self) {
        self.is_verified = true;
        self.updated_at = Utc::now();
    }

    /// 设置角色
    pub fn set_role(&mut self, role: String) {
        self.role = role;
        self.updated_at = Utc::now();
    }

    /// 更新资料
    pub fn update_profile(&mut self, profile: UserProfile) {
        self.profile = Some(profile);
        self.updated_at = Utc::now();
    }
}

// ============ 用户存储 ============

#[derive(Debug, Default)]
pub struct UserStore {
    users: Vec<User>,
}

impl UserStore {
    pub fn new() -> Self {
        Self { users: Vec::new() }
    }

    /// 添加用户
    pub fn add_user(&mut self, user: User) {
        self.users.push(user);
    }

    /// 按 ID 查找
    pub fn get_user_by_id(&self, id: &Uuid) -> Option<&User> {
        self.users.iter().find(|u| u.id == *id)
    }

    /// 按用户名查找
    pub fn get_user_by_username(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }

    /// 按邮箱查找
    pub fn get_user_by_email(&self, email: &str) -> Option<&User> {
        self.users.iter().find(|u| u.email == email)
    }

    /// 获取全部用户
    pub fn get_all_users(&self) -> &Vec<User> {
        &self.users
    }

    /// 删除用户
    pub fn remove_user(&mut self, id: &Uuid) -> bool {
        if let Some(pos) = self.users.iter().position(|u| u.id == *id) {
            self.users.remove(pos);
            true
        } else {
            false
        }
    }

    /// 更新用户
    pub fn update_user(&mut self, user: User) -> bool {
        if let Some(pos) = self.users.iter().position(|u| u.id == user.id) {
            self.users[pos] = user;
            true
        } else {
            false
        }
    }

    /// 查找或创建 SSO 用户
    pub fn find_or_create_sso_user(
        &mut self,
        email: &str,
        username: &str,
    ) -> Option<&User> {
        if let Some(pos) = self.users.iter().position(|u| u.email == email) {
            Some(&self.users[pos])
        } else {
            let user = User::from_sso(username.to_string(), email.to_string());
            self.users.push(user);
            self.users.last()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new("alice".to_string(), "alice@example.com".to_string(), "password123".to_string());
        assert!(user.is_ok());
        let user = user.unwrap();
        assert_eq!(user.username, "alice");
        assert!(user.password_hash.is_some());
        assert!(user.verify_password("password123"));
        assert!(!user.verify_password("wrong"));
    }

    #[test]
    fn test_user_from_sso() {
        let user = User::from_sso("bob".to_string(), "bob@example.com".to_string());
        assert_eq!(user.username, "bob");
        assert!(user.password_hash.is_none());
        assert!(user.is_verified);
    }

    #[test]
    fn test_user_store() {
        let mut store = UserStore::new();
        let user = User::new("alice".to_string(), "alice@example.com".to_string(), "pass".to_string()).unwrap();
        let id = user.id;
        store.add_user(user);

        assert!(store.get_user_by_id(&id).is_some());
        assert!(store.get_user_by_username("alice").is_some());
        assert!(store.get_user_by_email("alice@example.com").is_some());

        store.remove_user(&id);
        assert!(store.get_user_by_id(&id).is_none());
    }

    #[test]
    fn test_find_or_create_sso_user() {
        let mut store = UserStore::new();
        let user = store.find_or_create_sso_user("sso@example.com", "sso_user");
        assert!(user.is_some());

        let user2 = store.find_or_create_sso_user("sso@example.com", "sso_user");
        assert_eq!(user.unwrap().id, user2.unwrap().id);
    }
}