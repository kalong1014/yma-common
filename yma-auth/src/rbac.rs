use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// 资源操作权限
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub resource: String,
    pub action: String,
}

/// 角色定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
    pub parent: Option<String>,
}

/// RBAC 引擎
pub struct RbacEngine {
    roles: RwLock<HashMap<String, Role>>,
    user_roles: RwLock<HashMap<String, Vec<String>>>,
}

impl RbacEngine {
    pub fn new() -> Self {
        Self {
            roles: RwLock::new(HashMap::new()),
            user_roles: RwLock::new(HashMap::new()),
        }
    }

    /// 定义角色
    pub fn define_role(&self, name: &str, permissions: Vec<Permission>, parent: Option<String>) {
        let mut roles = self.roles.write();
        roles.insert(name.to_string(), Role {
            name: name.to_string(),
            permissions,
            parent,
        });
    }

    /// 为用户分配角色
    pub fn assign_role(&self, user_id: &str, role_name: &str) {
        let mut user_roles = self.user_roles.write();
        user_roles.entry(user_id.to_string())
            .or_default()
            .push(role_name.to_string());
    }

    /// 获取用户的所有权限
    pub fn list_permissions(&self, user_id: &str) -> Vec<Permission> {
        let user_roles = self.user_roles.read();
        let roles = self.roles.read();
        let mut result = Vec::new();

        if let Some(role_names) = user_roles.get(user_id) {
            let mut seen = HashSet::new();
            for role_name in role_names {
                self.collect_permissions(role_name, &roles, &mut result, &mut seen);
            }
        }

        result
    }

    fn collect_permissions(
        &self,
        role_name: &str,
        roles: &HashMap<String, Role>,
        result: &mut Vec<Permission>,
        seen: &mut HashSet<String>,
    ) {
        if !seen.insert(role_name.to_string()) {
            return;
        }

        if let Some(role) = roles.get(role_name) {
            for perm in &role.permissions {
                let key = format!("{}:{}", perm.resource, perm.action);
                if seen.insert(key) {
                    result.push(perm.clone());
                }
            }
            if let Some(ref parent) = role.parent {
                self.collect_permissions(parent, roles, result, seen);
            }
        }
    }

    /// 检查权限（支持 `*` 通配符匹配）
    pub fn check_permission(&self, user_id: &str, resource: &str, action: &str) -> bool {
        let permissions = self.list_permissions(user_id);
        permissions.iter().any(|p| {
            (p.resource == "*" || p.resource == resource) &&
            (p.action == "*" || p.action == action)
        })
    }
}

impl Default for RbacEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbac_basic() {
        let engine = RbacEngine::new();
        engine.define_role("admin", vec![
            Permission { resource: "*".to_string(), action: "*".to_string() },
        ], None);
        engine.define_role("viewer", vec![
            Permission { resource: "report".to_string(), action: "read".to_string() },
        ], None);

        engine.assign_role("user1", "admin");
        engine.assign_role("user2", "viewer");

        assert!(engine.check_permission("user1", "config", "write"));
        assert!(engine.check_permission("user2", "report", "read"));
        assert!(!engine.check_permission("user2", "config", "write"));
    }

    #[test]
    fn test_rbac_role_hierarchy() {
        let engine = RbacEngine::new();
        engine.define_role("base", vec![
            Permission { resource: "dashboard".to_string(), action: "read".to_string() },
        ], None);
        engine.define_role("manager", vec![
            Permission { resource: "users".to_string(), action: "write".to_string() },
        ], Some("base".to_string()));

        engine.assign_role("user_mgr", "manager");

        assert!(engine.check_permission("user_mgr", "dashboard", "read"));
        assert!(engine.check_permission("user_mgr", "users", "write"));
    }

    #[test]
    fn test_rbac_no_permission() {
        let engine = RbacEngine::new();
        engine.assign_role("user_guest", "nonexistent_role");
        assert!(!engine.check_permission("user_guest", "anything", "read"));
    }
}