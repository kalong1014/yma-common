//! yma-auth::permission — 权限定义与存储
//!
//! 注意：此 Permission 与 yma_auth::rbac::Permission 不同
//! yma_auth::rbac::Permission = {resource: String, action: String}（资源-动作模型）
//! 此 Permission = {id, name, description, code}（Code-based 权限模型）

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============ 权限定义 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub code: String,
}

impl Permission {
    pub fn new(name: String, description: String, code: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            code,
        }
    }
}

// ============ 权限存储 ============

#[derive(Debug, Default)]
pub struct PermissionStore {
    permissions: Vec<Permission>,
}

impl PermissionStore {
    pub fn new() -> Self {
        Self {
            permissions: Vec::new(),
        }
    }

    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.push(permission);
    }

    /// 按 ID 查找
    pub fn get_permission_by_id(&self, id: &Uuid) -> Option<&Permission> {
        self.permissions.iter().find(|p| p.id == *id)
    }

    /// 按代码查找（如 "user:manage"）
    pub fn get_permission_by_code(&self, code: &str) -> Option<&Permission> {
        self.permissions.iter().find(|p| p.code == code)
    }

    /// 获取全部权限
    pub fn get_all_permissions(&self) -> &Vec<Permission> {
        &self.permissions
    }

    /// 删除权限
    pub fn remove_permission(&mut self, id: &Uuid) -> bool {
        if let Some(pos) = self.permissions.iter().position(|p| p.id == *id) {
            self.permissions.remove(pos);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_new() {
        let perm = Permission::new(
            "用户管理".to_string(),
            "管理用户账户".to_string(),
            "user:manage".to_string(),
        );
        assert_eq!(perm.name, "用户管理");
        assert_eq!(perm.code, "user:manage");
    }

    #[test]
    fn test_permission_store() {
        let mut store = PermissionStore::new();
        let perm = Permission::new("测试".to_string(), "描述".to_string(), "test:code".to_string());
        let id = perm.id;
        store.add_permission(perm);

        assert!(store.get_permission_by_id(&id).is_some());
        assert!(store.get_permission_by_code("test:code").is_some());

        store.remove_permission(&id);
        assert!(store.get_permission_by_id(&id).is_none());
    }
}