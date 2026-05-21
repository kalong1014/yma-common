//! yma-auth::session_refresh — Session Refresh Token 生命周期管理
//!
//! 提供 Refresh Token 的签发、轮换、撤销和过期管理

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Refresh Token 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub token_id: String,
    pub user_id: Uuid,
    pub token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rotated_from: Option<String>, // 轮换链：此 token 是从哪个 token 轮换来的
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
    pub device_info: Option<String>,
    pub ip_address: Option<String>,
}

/// Refresh Token 状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshTokenStatus {
    Valid,
    Expired,
    Revoked,
    Rotated, // 已被轮换，新 token 已签发
}

/// Refresh Token 存储与生命周期管理器
#[derive(Debug, Default)]
pub struct RefreshTokenManager {
    tokens: HashMap<String, RefreshTokenRecord>, // token_hash -> record
    user_tokens: HashMap<Uuid, Vec<String>>,     // user_id -> token_hashes
    config: RefreshTokenConfig,
}

/// Refresh Token 配置
#[derive(Debug, Clone)]
pub struct RefreshTokenConfig {
    /// Refresh Token 有效期（天）
    pub ttl_days: i64,
    /// 是否启用 token 轮换
    pub rotation_enabled: bool,
    /// 轮换宽限期（分钟）：旧 token 在轮换后仍可使用的时间
    pub rotation_grace_period_minutes: i64,
    /// 每个用户最大并发 refresh token 数
    pub max_tokens_per_user: usize,
    /// 是否在检测到重放时撤销所有用户 token
    pub revoke_all_on_replay: bool,
}

impl Default for RefreshTokenConfig {
    fn default() -> Self {
        Self {
            ttl_days: 30,
            rotation_enabled: true,
            rotation_grace_period_minutes: 5,
            max_tokens_per_user: 5,
            revoke_all_on_replay: true,
        }
    }
}

impl RefreshTokenManager {
    pub fn new() -> Self {
        Self::with_config(RefreshTokenConfig::default())
    }

    pub fn with_config(config: RefreshTokenConfig) -> Self {
        Self {
            tokens: HashMap::new(),
            user_tokens: HashMap::new(),
            config,
        }
    }

    /// 签发新的 Refresh Token
    pub fn issue_token(
        &mut self,
        user_id: Uuid,
        device_info: Option<String>,
        ip_address: Option<String>,
    ) -> Result<String, String> {
        // 检查用户 token 数量限制
        let user_token_count = self.user_tokens.get(&user_id).map(|v| v.len()).unwrap_or(0);
        if user_token_count >= self.config.max_tokens_per_user {
            return Err(format!(
                "Max refresh tokens per user ({}) exceeded",
                self.config.max_tokens_per_user
            ));
        }

        let token_id = Uuid::new_v4().to_string();
        let token_value = format!("{}.{}", token_id, generate_random_string(32));
        let token_hash = hash_token(&token_value);

        let now = Utc::now();
        let record = RefreshTokenRecord {
            token_id: token_id.clone(),
            user_id,
            token_hash: token_hash.clone(),
            issued_at: now,
            expires_at: now + Duration::days(self.config.ttl_days),
            rotated_from: None,
            revoked_at: None,
            revoked_reason: None,
            device_info,
            ip_address,
        };

        self.tokens.insert(token_hash.clone(), record);
        self.user_tokens
            .entry(user_id)
            .or_default()
            .push(token_hash);

        Ok(token_value)
    }

    /// 验证 Refresh Token
    pub fn validate_token(&self, token_value: &str) -> Result<RefreshTokenRecord, String> {
        let token_hash = hash_token(token_value);
        let record = self
            .tokens
            .get(&token_hash)
            .ok_or("Invalid refresh token")?;

        match self.get_token_status(record) {
            RefreshTokenStatus::Valid => Ok(record.clone()),
            RefreshTokenStatus::Expired => Err("Refresh token expired".to_string()),
            RefreshTokenStatus::Revoked => Err("Refresh token revoked".to_string()),
            RefreshTokenStatus::Rotated => {
                // 检查是否在宽限期内
                if let Some(grace_period) = self.check_rotation_grace(record) {
                    Ok(grace_period)
                } else {
                    Err("Refresh token already rotated".to_string())
                }
            }
        }
    }

    /// 轮换 Refresh Token（签发新 token，标记旧 token 为已轮换）
    pub fn rotate_token(
        &mut self,
        old_token_value: &str,
        device_info: Option<String>,
        ip_address: Option<String>,
    ) -> Result<String, String> {
        if !self.config.rotation_enabled {
            // 轮换未启用，直接返回原 token
            return Ok(old_token_value.to_string());
        }

        let old_token_hash = hash_token(old_token_value);
        let old_record = self
            .tokens
            .get(&old_token_hash)
            .ok_or("Invalid refresh token")?
            .clone();

        // 验证旧 token 状态
        match self.get_token_status(&old_record) {
            RefreshTokenStatus::Valid | RefreshTokenStatus::Rotated => {}
            RefreshTokenStatus::Expired => return Err("Refresh token expired".to_string()),
            RefreshTokenStatus::Revoked => return Err("Refresh token revoked".to_string()),
        }

        // 标记旧 token 为已轮换
        if let Some(record) = self.tokens.get_mut(&old_token_hash) {
            record.rotated_from = Some(old_record.token_id.clone());
        }

        // 签发新 token
        let new_token = self.issue_token(
            old_record.user_id,
            device_info,
            ip_address,
        )?;

        Ok(new_token)
    }

    /// 撤销指定 Refresh Token
    pub fn revoke_token(&mut self, token_value: &str, reason: &str) -> bool {
        let token_hash = hash_token(token_value);
        if let Some(record) = self.tokens.get_mut(&token_hash) {
            record.revoked_at = Some(Utc::now());
            record.revoked_reason = Some(reason.to_string());
            true
        } else {
            false
        }
    }

    /// 撤销用户的所有 Refresh Token
    pub fn revoke_all_user_tokens(&mut self, user_id: &Uuid, reason: &str) -> usize {
        let mut count = 0;
        if let Some(token_hashes) = self.user_tokens.get(user_id) {
            for hash in token_hashes.clone() {
                if let Some(record) = self.tokens.get_mut(&hash) {
                    if record.revoked_at.is_none() {
                        record.revoked_at = Some(Utc::now());
                        record.revoked_reason = Some(reason.to_string());
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// 获取 token 状态
    pub fn get_token_status(&self, record: &RefreshTokenRecord) -> RefreshTokenStatus {
        if record.revoked_at.is_some() {
            return RefreshTokenStatus::Revoked;
        }
        if Utc::now() > record.expires_at {
            return RefreshTokenStatus::Expired;
        }
        if record.rotated_from.is_some() {
            return RefreshTokenStatus::Rotated;
        }
        RefreshTokenStatus::Valid
    }

    /// 检查轮换宽限期
    fn check_rotation_grace(&self, record: &RefreshTokenRecord) -> Option<RefreshTokenRecord> {
        // 如果 token 被标记为轮换，检查是否在宽限期内
        // 简化实现：如果 token 在宽限期内被使用，允许一次
        let grace_end = record.issued_at
            + Duration::minutes(self.config.rotation_grace_period_minutes);
        if Utc::now() <= grace_end {
            Some(record.clone())
        } else {
            None
        }
    }

    /// 清理过期 token
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .tokens
            .iter()
            .filter(|(_, r)| now > r.expires_at && r.revoked_at.is_none())
            .map(|(h, _)| h.clone())
            .collect();

        for hash in &expired {
            if let Some(record) = self.tokens.remove(hash) {
                if let Some(list) = self.user_tokens.get_mut(&record.user_id) {
                    list.retain(|h| h != hash);
                }
            }
        }
        expired.len()
    }

    /// 获取用户的所有 token
    pub fn get_user_tokens(&self, user_id: &Uuid) -> Vec<&RefreshTokenRecord> {
        self.user_tokens
            .get(user_id)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| self.tokens.get(h))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 获取有效 token 数量
    pub fn valid_token_count(&self) -> usize {
        self.tokens
            .values()
            .filter(|r| self.get_token_status(r) == RefreshTokenStatus::Valid)
            .count()
    }
}

/// 生成随机字符串
fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// 哈希 token（存储时只存哈希）
fn hash_token(token: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_token() {
        let mut manager = RefreshTokenManager::new();
        let user_id = Uuid::new_v4();

        let token = manager.issue_token(user_id, None, None).unwrap();
        assert!(!token.is_empty());
        assert!(token.contains('.'));
    }

    #[test]
    fn test_validate_token() {
        let mut manager = RefreshTokenManager::new();
        let user_id = Uuid::new_v4();

        let token = manager.issue_token(user_id, None, None).unwrap();
        let record = manager.validate_token(&token).unwrap();
        assert_eq!(record.user_id, user_id);
    }

    #[test]
    fn test_rotate_token() {
        let mut manager = RefreshTokenManager::new();
        let user_id = Uuid::new_v4();

        let old_token = manager.issue_token(user_id, None, None).unwrap();
        let new_token = manager.rotate_token(&old_token, None, None).unwrap();

        assert_ne!(old_token, new_token);

        // 旧 token 应该被标记为轮换
        let old_record = manager.validate_token(&old_token);
        assert!(old_record.is_err() || manager.get_token_status(&old_record.unwrap()) == RefreshTokenStatus::Rotated);

        // 新 token 应该有效
        let new_record = manager.validate_token(&new_token).unwrap();
        assert_eq!(manager.get_token_status(&new_record), RefreshTokenStatus::Valid);
    }

    #[test]
    fn test_revoke_token() {
        let mut manager = RefreshTokenManager::new();
        let user_id = Uuid::new_v4();

        let token = manager.issue_token(user_id, None, None).unwrap();
        assert!(manager.revoke_token(&token, "User logout"));

        let result = manager.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_all_user_tokens() {
        let mut manager = RefreshTokenManager::new();
        let user_id = Uuid::new_v4();

        manager.issue_token(user_id, None, None).unwrap();
        manager.issue_token(user_id, None, None).unwrap();

        let count = manager.revoke_all_user_tokens(&user_id, "Security breach");
        assert_eq!(count, 2);

        let tokens = manager.get_user_tokens(&user_id);
        assert!(tokens.iter().all(|t| t.revoked_at.is_some()));
    }

    #[test]
    fn test_max_tokens_per_user() {
        let mut manager = RefreshTokenManager::with_config(RefreshTokenConfig {
            max_tokens_per_user: 2,
            ..Default::default()
        });
        let user_id = Uuid::new_v4();

        manager.issue_token(user_id, None, None).unwrap();
        manager.issue_token(user_id, None, None).unwrap();

        let result = manager.issue_token(user_id, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut manager = RefreshTokenManager::with_config(RefreshTokenConfig {
            ttl_days: 0, // 立即过期
            ..Default::default()
        });
        let user_id = Uuid::new_v4();

        manager.issue_token(user_id, None, None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);
    }
}