//! yma-auth::role — 角色枚举与角色定义
//!
//! 提供10级等级制角色系统 + 角色定义存储

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============ 角色枚举（10级等级制+自定义） ============

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
    Guest,
    Level10,
    Level9,
    Level8,
    Level7,
    Level6,
    Level5,
    Level4,
    Level3,
    Level2,
    Level1,
    Custom(String, i32),
}

impl Role {
    /// 获取角色代码（如 "admin", "level_5"）
    pub fn code(&self) -> String {
        match self {
            Role::Admin => "admin".to_string(),
            Role::User => "user".to_string(),
            Role::Guest => "guest".to_string(),
            Role::Level10 => "level_10".to_string(),
            Role::Level9 => "level_9".to_string(),
            Role::Level8 => "level_8".to_string(),
            Role::Level7 => "level_7".to_string(),
            Role::Level6 => "level_6".to_string(),
            Role::Level5 => "level_5".to_string(),
            Role::Level4 => "level_4".to_string(),
            Role::Level3 => "level_3".to_string(),
            Role::Level2 => "level_2".to_string(),
            Role::Level1 => "level_1".to_string(),
            Role::Custom(name, _) => name.clone(),
        }
    }

    /// 获取角色显示名
    pub fn name(&self) -> String {
        match self {
            Role::Admin => "系统管理员".to_string(),
            Role::User => "普通用户".to_string(),
            Role::Guest => "访客".to_string(),
            Role::Level10 => "等级10".to_string(),
            Role::Level9 => "超级管理员".to_string(),
            Role::Level8 => "高级管理员".to_string(),
            Role::Level7 => "管理员".to_string(),
            Role::Level6 => "高级用户".to_string(),
            Role::Level5 => "等级5".to_string(),
            Role::Level4 => "受限用户".to_string(),
            Role::Level3 => "等级3".to_string(),
            Role::Level2 => "临时用户".to_string(),
            Role::Level1 => "匿名用户".to_string(),
            Role::Custom(name, _) => name.clone(),
        }
    }

    /// 获取角色等级值（Admin=10, User=5, Guest=3, Level10=10 ... Level1=1）
    pub fn level(&self) -> i32 {
        match self {
            Role::Admin | Role::Level10 => 10,
            Role::Level9 => 9,
            Role::Level8 => 8,
            Role::Level7 => 7,
            Role::Level6 => 6,
            Role::User | Role::Level5 => 5,
            Role::Level4 => 4,
            Role::Guest | Role::Level3 => 3,
            Role::Level2 => 2,
            Role::Level1 => 1,
            Role::Custom(_, level) => *level,
        }
    }

    /// 检查当前角色权限是否 >= 目标角色
    pub fn has_permission(&self, required: &Self) -> bool {
        self.level() >= required.level()
    }

    /// 从等级值构造角色
    pub fn from_level(level: i32) -> Self {
        match level {
            10 => Role::Level10,
            9 => Role::Level9,
            8 => Role::Level8,
            7 => Role::Level7,
            6 => Role::Level6,
            5 => Role::Level5,
            4 => Role::Level4,
            3 => Role::Level3,
            2 => Role::Level2,
            1 => Role::Level1,
            _ => Role::Custom(format!("level_{}", level), level),
        }
    }
}

// ============ 角色定义（数据库/存储用） ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub code: String,
    pub level: i32,
    pub permission_ids: Vec<Uuid>,
    pub parent_role_id: Option<Uuid>,
    pub is_system_role: bool,
}

impl RoleDefinition {
    /// 创建自定义角色
    pub fn new(name: String, description: String, code: String, level: i32) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            code,
            level,
            permission_ids: Vec::new(),
            parent_role_id: None,
            is_system_role: false,
        }
    }

    /// 创建系统预置角色
    pub fn new_system_role(name: String, description: String, code: String, level: i32) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            code,
            level,
            permission_ids: Vec::new(),
            parent_role_id: None,
            is_system_role: true,
        }
    }

    /// 添加权限
    pub fn add_permission(&mut self, permission_id: Uuid) {
        if !self.permission_ids.contains(&permission_id) {
            self.permission_ids.push(permission_id);
        }
    }

    /// 移除权限
    pub fn remove_permission(&mut self, permission_id: &Uuid) -> bool {
        if let Some(pos) = self.permission_ids.iter().position(|id| id == permission_id) {
            self.permission_ids.remove(pos);
            true
        } else {
            false
        }
    }

    /// 检查是否拥有该权限
    pub fn has_permission(&self, permission_id: &Uuid) -> bool {
        self.permission_ids.contains(permission_id)
    }

    /// 递归检查（含父角色继承链）
    pub fn has_permission_recursive(&self, permission_id: &Uuid, role_store: &RoleStore) -> bool {
        if self.has_permission(permission_id) {
            return true;
        }
        if let Some(parent_id) = self.parent_role_id {
            if let Some(parent) = role_store.get_role_by_id(&parent_id) {
                return parent.has_permission_recursive(permission_id, role_store);
            }
        }
        false
    }
}

// ============ 角色存储 ============

#[derive(Debug)]
pub struct RoleStore {
    roles: Vec<RoleDefinition>,
}

impl Default for RoleStore {
    fn default() -> Self {
        let mut store = Self { roles: Vec::new() };
        store.init_system_roles();
        store
    }
}

impl RoleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 初始化10个系统预置角色
    fn init_system_roles(&mut self) {
        let system_roles = vec![
            ("系统管理员", "拥有所有权限", "admin", 10),
            ("超级管理员", "高级管理权限", "level_9", 9),
            ("高级管理员", "管理权限", "level_8", 8),
            ("管理员", "基础管理权限", "level_7", 7),
            ("高级用户", "高级用户权限", "level_6", 6),
            ("普通用户", "标准用户权限", "user", 5),
            ("受限用户", "受限权限", "level_4", 4),
            ("访客", "仅浏览权限", "guest", 3),
            ("临时用户", "临时访问权限", "level_2", 2),
            ("匿名用户", "最低权限", "level_1", 1),
        ];

        for (name, desc, code, level) in system_roles {
            self.roles.push(RoleDefinition::new_system_role(
                name.to_string(),
                desc.to_string(),
                code.to_string(),
                level,
            ));
        }
    }

    /// 添加角色（code 重复时跳过）
    pub fn add_role(&mut self, role: RoleDefinition) {
        if !self.roles.iter().any(|r| r.code == role.code) {
            self.roles.push(role);
        }
    }

    /// 按 ID 查找
    pub fn get_role_by_id(&self, id: &Uuid) -> Option<&RoleDefinition> {
        self.roles.iter().find(|r| r.id == *id)
    }

    /// 按 code 查找
    pub fn get_role_by_code(&self, code: &str) -> Option<&RoleDefinition> {
        self.roles.iter().find(|r| r.code == code)
    }

    /// 按等级查找系统角色
    pub fn get_role_by_level(&self, level: i32) -> Option<&RoleDefinition> {
        self.roles.iter().find(|r| r.level == level && r.is_system_role)
    }

    /// 获取全部角色
    pub fn get_all_roles(&self) -> &Vec<RoleDefinition> {
        &self.roles
    }

    /// 获取系统角色
    pub fn get_system_roles(&self) -> Vec<&RoleDefinition> {
        self.roles.iter().filter(|r| r.is_system_role).collect()
    }

    /// 获取自定义角色
    pub fn get_custom_roles(&self) -> Vec<&RoleDefinition> {
        self.roles.iter().filter(|r| !r.is_system_role).collect()
    }

    /// 删除角色（系统角色不可删除）
    pub fn remove_role(&mut self, id: &Uuid) -> bool {
        if let Some(pos) = self.roles.iter().position(|r| r.id == *id) {
            if self.roles[pos].is_system_role {
                return false;
            }
            self.roles.remove(pos);
            true
        } else {
            false
        }
    }

    /// 更新角色（系统角色不可降级为自定义角色）
    pub fn update_role(&mut self, role: RoleDefinition) -> bool {
        if let Some(pos) = self.roles.iter().position(|r| r.id == role.id) {
            if self.roles[pos].is_system_role && !role.is_system_role {
                return false;
            }
            self.roles[pos] = role;
            true
        } else {
            false
        }
    }

    /// 获取低于指定等级的角色
    pub fn get_roles_below_level(&self, level: i32) -> Vec<&RoleDefinition> {
        self.roles.iter().filter(|r| r.level < level).collect()
    }

    /// 获取高于指定等级的角色
    pub fn get_roles_above_level(&self, level: i32) -> Vec<&RoleDefinition> {
        self.roles.iter().filter(|r| r.level > level).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_level() {
        assert_eq!(Role::Admin.level(), 10);
        assert_eq!(Role::User.level(), 5);
        assert_eq!(Role::Guest.level(), 3);
        assert_eq!(Role::Level1.level(), 1);
        assert_eq!(Role::Custom("test".to_string(), 7).level(), 7);
    }

    #[test]
    fn test_role_has_permission() {
        assert!(Role::Admin.has_permission(&Role::User));
        assert!(Role::User.has_permission(&Role::Guest));
        assert!(!Role::Guest.has_permission(&Role::Admin));
    }

    #[test]
    fn test_role_store_init() {
        let store = RoleStore::new();
        assert_eq!(store.get_all_roles().len(), 10);
        assert_eq!(store.get_system_roles().len(), 10);
        assert_eq!(store.get_custom_roles().len(), 0);
    }

    #[test]
    fn test_role_store_operations() {
        let mut store = RoleStore::new();

        let custom = RoleDefinition::new("测试".to_string(), "测试角色".to_string(), "test".to_string(), 5);
        let id = custom.id;
        store.add_role(custom);

        assert!(store.get_role_by_id(&id).is_some());
        assert!(store.get_role_by_code("test").is_some());

        // 系统角色不可删除
        let admin = store.get_role_by_code("admin").unwrap();
        assert!(!store.remove_role(&admin.id));

        // 自定义角色可删除
        assert!(store.remove_role(&id));
    }

    #[test]
    fn test_role_definition_permissions() {
        let mut role = RoleDefinition::new("测试".to_string(), "描述".to_string(), "test".to_string(), 5);
        let perm_id = Uuid::new_v4();

        role.add_permission(perm_id);
        assert!(role.has_permission(&perm_id));

        role.remove_permission(&perm_id);
        assert!(!role.has_permission(&perm_id));
    }
}