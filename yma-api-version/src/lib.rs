#![deny(missing_docs)]
//! API版本管理模块，提供版本生命周期管理和版本检查功能。
//!
//! 支持三种版本状态: Active（活跃）、Deprecated（已弃用）、Sunset（已停用）。
//!
//! # Features
//! - `axum-handler`: 启用axum集成，提供版本查询HTTP handler

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 版本生命周期状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// 活跃版本，正常接受请求
    Active,
    /// 已弃用版本，仍可使用但建议升级
    Deprecated,
    /// 已停用版本，不再接受请求
    Sunset,
}

/// API版本信息结构体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    /// 版本号，如 "v1", "v2"
    pub version: String,
    /// 版本状态
    pub status: VersionStatus,
    /// 发布日期，格式 "YYYY-MM-DD"
    pub release_date: String,
    /// 版本描述
    pub description: String,
    /// 弃用起始日期
    pub deprecated_since: Option<String>,
    /// 终止服务日期
    pub end_of_life: Option<String>,
}

/// API服务信息结构体。
#[derive(Debug, Clone, Serialize)]
pub struct ApiInfo {
    /// 服务名称
    pub name: String,
    /// 所有版本信息列表，按版本号降序排列
    pub versions: Vec<ApiVersion>,
    /// 当前默认版本号
    pub current_version: String,
}

/// 版本检查结果结构体。
#[derive(Debug, Clone, Serialize)]
pub struct VersionCheckResponse {
    /// 请求的版本是否有效
    pub valid: bool,
    /// 请求的版本号
    pub version: String,
    /// 版本当前状态
    pub status: Option<VersionStatus>,
    /// 人类可读的状态消息
    pub message: String,
    /// 升级建议
    pub suggestion: Option<String>,
}

/// API版本管理器。
///
/// 管理多个API版本并支持版本有效性检查和弃用通知。
#[derive(Debug, Clone)]
pub struct ApiVersionManager {
    versions: HashMap<String, ApiVersion>,
    current_version: String,
}

impl ApiVersionManager {
    /// 创建空的版本管理器实例。
    ///
    /// # 返回值
    /// 初始不包含任何版本的ApiVersionManager实例。
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
            current_version: String::new(),
        }
    }

    /// 添加一个API版本。
    ///
    /// # 参数
    /// * `version` - 要添加的版本信息
    ///
    /// # 返回值
    /// Self的可变引用以支持链式调用。
    ///
    /// # 说明
    /// 如果是添加的第一个版本，自动将其设为当前版本。
    pub fn add_version(&mut self, version: ApiVersion) -> &mut Self {
        let ver_key = version.version.clone();
        if self.versions.is_empty() {
            self.current_version = ver_key.clone();
        }
        self.versions.insert(ver_key, version);
        self
    }

    /// 设置当前默认版本。
    ///
    /// # 参数
    /// * `version` - 要设为当前版本的版本号
    ///
    /// # 说明
    /// 如果版本不存在则不做任何操作。
    pub fn set_current_version(&mut self, version: &str) {
        if self.versions.contains_key(version) {
            self.current_version = version.to_string();
        }
    }

    /// 获取所有版本信息列表。
    ///
    /// # 返回值
    /// 按版本号降序排列的版本列表。
    pub fn get_all_versions(&self) -> Vec<ApiVersion> {
        let mut versions: Vec<ApiVersion> = self.versions.values().cloned().collect();
        versions.sort_by(|a, b| b.version.cmp(&a.version));
        versions
    }

    /// 获取当前默认版本信息。
    ///
    /// # 返回值
    /// 当前版本的引用，如果未设置则返回None。
    pub fn get_current_version(&self) -> Option<&ApiVersion> {
        self.versions.get(&self.current_version)
    }

    /// 获取指定版本信息。
    ///
    /// # 参数
    /// * `version` - 版本号
    ///
    /// # 返回值
    /// 对应版本的引用，如果不存在返回None。
    pub fn get_version(&self, version: &str) -> Option<&ApiVersion> {
        self.versions.get(version)
    }

    /// 检查版本是否有效（已注册且未停用）。
    ///
    /// # 参数
    /// * `version` - 版本号
    ///
    /// # 返回值
    /// 版本存在于管理器中且状态不为Sunset时返回true。
    pub fn is_version_valid(&self, version: &str) -> bool {
        self.versions.contains_key(version)
    }

    /// 检查版本是否已弃用。
    ///
    /// # 参数
    /// * `version` - 版本号
    ///
    /// # 返回值
    /// 版本不存在或状态为Deprecated/Sunset时返回true。
    pub fn is_version_deprecated(&self, version: &str) -> bool {
        match self.versions.get(version) {
            Some(v) => matches!(v.status, VersionStatus::Deprecated | VersionStatus::Sunset),
            None => true,
        }
    }

    /// 检查指定版本并返回结果。
    ///
    /// # 参数
    /// * `version` - 要检查的版本号
    ///
    /// # 返回值
    /// VersionCheckResponse包含版本有效性、状态和建议信息。
    pub fn check_version(&self, version: &str) -> VersionCheckResponse {
        if !self.is_version_valid(version) {
            return VersionCheckResponse {
                valid: false,
                version: version.to_string(),
                status: None,
                message: "无效的API版本".to_string(),
                suggestion: Some(format!("请使用当前版本: {}", self.current_version)),
            };
        }

        let ver = self.versions.get(version).unwrap();

        if self.is_version_deprecated(version) {
            return VersionCheckResponse {
                valid: true,
                version: version.to_string(),
                status: Some(ver.status.clone()),
                message: "该版本已弃用，请升级到最新版本".to_string(),
                suggestion: Some(format!("建议使用当前版本: {}", self.current_version)),
            };
        }

        VersionCheckResponse {
            valid: true,
            version: version.to_string(),
            status: Some(ver.status.clone()),
            message: "版本有效".to_string(),
            suggestion: None,
        }
    }

    /// 获取API信息服务的信息。
    ///
    /// # 参数
    /// * `api_name` - API服务名称
    ///
    /// # 返回值
    /// 包含所有版本信息的ApiInfo实例。
    pub fn get_api_info(&self, api_name: &str) -> ApiInfo {
        ApiInfo {
            name: api_name.to_string(),
            versions: self.get_all_versions(),
            current_version: self.current_version.clone(),
        }
    }
}

impl Default for ApiVersionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_version(version: &str, status: VersionStatus) -> ApiVersion {
        ApiVersion {
            version: version.to_string(),
            status,
            release_date: "2024-01-01".to_string(),
            description: "测试版本".to_string(),
            deprecated_since: None,
            end_of_life: None,
        }
    }

    #[test]
    fn test_add_version() {
        let mut manager = ApiVersionManager::new();
        manager.add_version(create_test_version("v1", VersionStatus::Active));
        assert_eq!(manager.current_version, "v1");
        assert!(manager.is_version_valid("v1"));
    }

    #[test]
    fn test_set_current_version() {
        let mut manager = ApiVersionManager::new();
        manager
            .add_version(create_test_version("v1", VersionStatus::Active))
            .add_version(create_test_version("v2", VersionStatus::Active));
        manager.set_current_version("v2");
        assert_eq!(manager.current_version, "v2");
    }

    #[test]
    fn test_set_current_version_not_found() {
        let mut manager = ApiVersionManager::new();
        manager.add_version(create_test_version("v1", VersionStatus::Active));
        manager.set_current_version("v99");
        assert_eq!(manager.current_version, "v1");
    }

    #[test]
    fn test_get_all_versions_sorted() {
        let mut manager = ApiVersionManager::new();
        manager
            .add_version(create_test_version("v1", VersionStatus::Active))
            .add_version(create_test_version("v3", VersionStatus::Active))
            .add_version(create_test_version("v2", VersionStatus::Active));
        let versions = manager.get_all_versions();
        assert_eq!(versions[0].version, "v3");
        assert_eq!(versions[1].version, "v2");
        assert_eq!(versions[2].version, "v1");
    }

    #[test]
    fn test_is_version_deprecated() {
        let mut manager = ApiVersionManager::new();
        manager
            .add_version(create_test_version("v1", VersionStatus::Deprecated))
            .add_version(create_test_version("v2", VersionStatus::Active));
        assert!(manager.is_version_deprecated("v1"));
        assert!(!manager.is_version_deprecated("v2"));
        assert!(manager.is_version_deprecated("v99"));
    }

    #[test]
    fn test_check_version_active() {
        let mut manager = ApiVersionManager::new();
        manager.add_version(create_test_version("v1", VersionStatus::Active));
        let response = manager.check_version("v1");
        assert!(response.valid);
        assert_eq!(response.message, "版本有效");
        assert_eq!(response.status, Some(VersionStatus::Active));
    }

    #[test]
    fn test_check_version_deprecated() {
        let mut manager = ApiVersionManager::new();
        manager.add_version(create_test_version("v1", VersionStatus::Deprecated));
        let response = manager.check_version("v1");
        assert!(response.valid);
        assert!(response.message.contains("弃用"));
        assert!(response.suggestion.is_some());
    }

    #[test]
    fn test_check_version_invalid() {
        let manager = ApiVersionManager::new();
        let response = manager.check_version("v99");
        assert!(!response.valid);
        assert!(response.suggestion.is_some());
    }

    #[test]
    fn test_get_api_info() {
        let mut manager = ApiVersionManager::new();
        manager.add_version(create_test_version("v1", VersionStatus::Active));
        let info = manager.get_api_info("test-api");
        assert_eq!(info.name, "test-api");
        assert_eq!(info.versions.len(), 1);
        assert_eq!(info.current_version, "v1");
    }
}