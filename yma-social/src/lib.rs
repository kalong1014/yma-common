#![deny(missing_docs)]
//! 社交图谱抽象层，提供关注、取关、屏蔽、好友关系管理的基础接口

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 社交关系类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocialRelation {
    /// 关注
    Follow,
    /// 被关注
    FollowedBy,
    /// 互相关注（好友）
    Friend,
    /// 屏蔽
    Block,
    /// 被屏蔽
    BlockedBy,
    /// 无关系
    None,
}

/// 社交用户信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUser {
    /// 用户ID
    pub user_id: String,
    /// 用户名称
    pub username: String,
    /// 头像URL
    pub avatar_url: Option<String>,
    /// 关系类型
    pub relation: SocialRelation,
    /// 关系建立时间
    pub relation_created_at: Option<DateTime<Utc>>,
}

/// 社交图谱操作结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialResult {
    /// 是否成功
    pub success: bool,
    /// 错误信息
    pub error: Option<String>,
}

/// 社交图谱存储抽象
#[async_trait]
pub trait SocialGraphStore: Send + Sync {
    /// 关注用户
    async fn follow(&self, user_id: &str, target_id: &str) -> SocialResult;
    /// 取消关注
    async fn unfollow(&self, user_id: &str, target_id: &str) -> SocialResult;
    /// 屏蔽用户
    async fn block(&self, user_id: &str, target_id: &str) -> SocialResult;
    /// 取消屏蔽
    async fn unblock(&self, user_id: &str, target_id: &str) -> SocialResult;
    /// 检查两个用户之间的关系
    async fn get_relation(&self, user_id: &str, target_id: &str) -> SocialRelation;
    /// 获取关注列表
    async fn get_following(
        &self,
        user_id: &str,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<SocialUser>, String>;
    /// 获取粉丝列表
    async fn get_followers(
        &self,
        user_id: &str,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<SocialUser>, String>;
    /// 获取好友列表（互相关注）
    async fn get_friends(&self, user_id: &str) -> Result<Vec<SocialUser>, String>;
    /// 获取关注数量
    async fn following_count(&self, user_id: &str) -> Result<u64, String>;
    /// 获取粉丝数量
    async fn followers_count(&self, user_id: &str) -> Result<u64, String>;
}

/// 内存社交图谱存储（测试用）
pub struct MemorySocialGraphStore {
    followers: tokio::sync::RwLock<
        std::collections::HashMap<String, std::collections::HashSet<String>>,
    >,
    blocks: tokio::sync::RwLock<
        std::collections::HashMap<String, std::collections::HashSet<String>>,
    >,
    users: tokio::sync::RwLock<std::collections::HashMap<String, SocialUser>>,
}

impl MemorySocialGraphStore {
    /// 创建内存社交图谱存储
    pub fn new() -> Self {
        Self {
            followers: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            blocks: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            users: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册用户
    pub async fn register_user(&self, user_id: &str, username: &str) {
        let user = SocialUser {
            user_id: user_id.to_string(),
            username: username.to_string(),
            avatar_url: None,
            relation: SocialRelation::None,
            relation_created_at: None,
        };
        self.users.write().await.insert(user_id.to_string(), user);
    }
}

impl Default for MemorySocialGraphStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SocialGraphStore for MemorySocialGraphStore {
    async fn follow(&self, user_id: &str, target_id: &str) -> SocialResult {
        if user_id == target_id {
            return SocialResult {
                success: false,
                error: Some("不能关注自己".to_string()),
            };
        }

        let blocks = self.blocks.read().await;
        if let Some(blocked) = blocks.get(target_id) {
            if blocked.contains(user_id) {
                return SocialResult {
                    success: false,
                    error: Some("你已被该用户屏蔽".to_string()),
                };
            }
        }
        drop(blocks);

        self.followers
            .write()
            .await
            .entry(user_id.to_string())
            .or_default()
            .insert(target_id.to_string());

        SocialResult {
            success: true,
            error: None,
        }
    }

    async fn unfollow(&self, user_id: &str, target_id: &str) -> SocialResult {
        if let Some(following) = self.followers.write().await.get_mut(user_id) {
            following.remove(target_id);
        }

        SocialResult {
            success: true,
            error: None,
        }
    }

    async fn block(&self, user_id: &str, target_id: &str) -> SocialResult {
        if user_id == target_id {
            return SocialResult {
                success: false,
                error: Some("不能屏蔽自己".to_string()),
            };
        }

        self.unfollow(user_id, target_id).await;
        self.unfollow(target_id, user_id).await;

        self.blocks
            .write()
            .await
            .entry(user_id.to_string())
            .or_default()
            .insert(target_id.to_string());

        SocialResult {
            success: true,
            error: None,
        }
    }

    async fn unblock(&self, user_id: &str, target_id: &str) -> SocialResult {
        if let Some(blocks) = self.blocks.write().await.get_mut(user_id) {
            blocks.remove(target_id);
        }

        SocialResult {
            success: true,
            error: None,
        }
    }

    async fn get_relation(&self, user_id: &str, target_id: &str) -> SocialRelation {
        let blocks = self.blocks.read().await;
        if let Some(blocked) = blocks.get(user_id) {
            if blocked.contains(target_id) {
                return SocialRelation::Block;
            }
        }
        if let Some(blocked) = blocks.get(target_id) {
            if blocked.contains(user_id) {
                return SocialRelation::BlockedBy;
            }
        }
        drop(blocks);

        let followers = self.followers.read().await;
        let i_follow = followers
            .get(user_id)
            .map(|s| s.contains(target_id))
            .unwrap_or(false);
        let follows_me = followers
            .get(target_id)
            .map(|s| s.contains(user_id))
            .unwrap_or(false);

        match (i_follow, follows_me) {
            (true, true) => SocialRelation::Friend,
            (true, false) => SocialRelation::Follow,
            (false, true) => SocialRelation::FollowedBy,
            (false, false) => SocialRelation::None,
        }
    }

    async fn get_following(
        &self,
        user_id: &str,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<SocialUser>, String> {
        let followers = self.followers.read().await;
        let page = if page == 0 { 1 } else { page };
        let offset = ((page - 1) * page_size) as usize;

        let result: Vec<SocialUser> = if let Some(set) = followers.get(user_id) {
            let users = self.users.read().await;
            set.iter()
                .skip(offset)
                .take(page_size as usize)
                .filter_map(|uid| users.get(uid).cloned())
                .collect()
        } else {
            Vec::new()
        };

        Ok(result)
    }

    async fn get_followers(
        &self,
        user_id: &str,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<SocialUser>, String> {
        let followers = self.followers.read().await;
        let page = if page == 0 { 1 } else { page };
        let offset = ((page - 1) * page_size) as usize;

        let mut follower_ids: Vec<String> = Vec::new();
        for (uid, targets) in followers.iter() {
            if targets.contains(user_id) {
                follower_ids.push(uid.clone());
            }
        }

        let users = self.users.read().await;
        let result: Vec<SocialUser> = follower_ids
            .iter()
            .skip(offset)
            .take(page_size as usize)
            .filter_map(|uid| users.get(uid).cloned())
            .collect();

        Ok(result)
    }

    async fn get_friends(&self, user_id: &str) -> Result<Vec<SocialUser>, String> {
        let followers = self.followers.read().await;
        let mut friends = Vec::new();

        if let Some(following) = followers.get(user_id) {
            let users = self.users.read().await;
            for target_id in following {
                let follows_back = followers
                    .get(target_id)
                    .map(|s| s.contains(user_id))
                    .unwrap_or(false);
                if follows_back {
                    if let Some(user) = users.get(target_id).cloned() {
                        friends.push(user);
                    }
                }
            }
        }

        Ok(friends)
    }

    async fn following_count(&self, user_id: &str) -> Result<u64, String> {
        let count = self
            .followers
            .read()
            .await
            .get(user_id)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        Ok(count)
    }

    async fn followers_count(&self, user_id: &str) -> Result<u64, String> {
        let followers = self.followers.read().await;
        let count = followers
            .iter()
            .filter(|(_, targets)| targets.contains(user_id))
            .count() as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store() -> MemorySocialGraphStore {
        let store = MemorySocialGraphStore::new();
        store.register_user("u1", "user1").await;
        store.register_user("u2", "user2").await;
        store.register_user("u3", "user3").await;
        store
    }

    #[tokio::test]
    async fn test_follow_and_unfollow() {
        let store = create_test_store().await;

        let result = store.follow("u1", "u2").await;
        assert!(result.success);

        assert_eq!(store.following_count("u1").await.unwrap(), 1);
        assert_eq!(store.followers_count("u2").await.unwrap(), 1);

        let result = store.unfollow("u1", "u2").await;
        assert!(result.success);
        assert_eq!(store.following_count("u1").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_cannot_follow_self() {
        let store = create_test_store().await;
        let result = store.follow("u1", "u1").await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn test_block_and_unblock() {
        let store = create_test_store().await;

        let result = store.block("u1", "u2").await;
        assert!(result.success);

        let relation = store.get_relation("u1", "u2").await;
        assert_eq!(relation, SocialRelation::Block);

        let relation = store.get_relation("u2", "u1").await;
        assert_eq!(relation, SocialRelation::BlockedBy);

        let result = store.unblock("u1", "u2").await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_friend_relation() {
        let store = create_test_store().await;

        store.follow("u1", "u2").await;
        store.follow("u2", "u1").await;

        let relation = store.get_relation("u1", "u2").await;
        assert_eq!(relation, SocialRelation::Friend);
    }

    #[tokio::test]
    async fn test_get_following() {
        let store = create_test_store().await;
        store.follow("u1", "u2").await;
        store.follow("u1", "u3").await;

        let following = store.get_following("u1", 1, 10).await.unwrap();
        assert_eq!(following.len(), 2);
    }

    #[tokio::test]
    async fn test_get_followers() {
        let store = create_test_store().await;
        store.follow("u2", "u1").await;
        store.follow("u3", "u1").await;

        let followers = store.get_followers("u1", 1, 10).await.unwrap();
        assert_eq!(followers.len(), 2);
    }

    #[tokio::test]
    async fn test_get_friends() {
        let store = create_test_store().await;
        store.follow("u1", "u2").await;
        store.follow("u2", "u1").await;
        store.follow("u1", "u3").await;

        let friends = store.get_friends("u1").await.unwrap();
        assert_eq!(friends.len(), 1);
    }
}