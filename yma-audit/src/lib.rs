#![deny(missing_docs)]
//! 审计日志模块，记录用户操作并提供分页查询功能。
//!
//! 支持的操作类型: Create, Update, Delete, Login, Logout, Export, ConfigChange

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 审计操作类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    /// 创建操作
    Create,
    /// 更新操作
    Update,
    /// 删除操作
    Delete,
    /// 登录操作
    Login,
    /// 登出操作
    Logout,
    /// 导出操作
    Export,
    /// 配置变更
    ConfigChange,
    /// 其他操作
    Other(String),
}

impl AuditAction {
    /// 转换为数据库存储的字符串。
    pub fn as_str(&self) -> String {
        match self {
            AuditAction::Create => "Create".to_string(),
            AuditAction::Update => "Update".to_string(),
            AuditAction::Delete => "Delete".to_string(),
            AuditAction::Login => "Login".to_string(),
            AuditAction::Logout => "Logout".to_string(),
            AuditAction::Export => "Export".to_string(),
            AuditAction::ConfigChange => "ConfigChange".to_string(),
            AuditAction::Other(s) => s.clone(),
        }
    }
}

/// 审计记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// 记录ID
    pub id: String,
    /// 用户ID
    pub user_id: Option<String>,
    /// 用户名
    pub username: Option<String>,
    /// 操作类型
    pub action: String,
    /// 资源类型
    pub resource_type: String,
    /// 资源ID
    pub resource_id: Option<String>,
    /// 操作详情
    pub detail: String,
    /// 变更前数据（JSON字符串）
    pub before_data: Option<String>,
    /// 变更后数据（JSON字符串）
    pub after_data: Option<String>,
    /// 客户端IP地址
    pub ip_address: Option<String>,
    /// 用户代理
    pub user_agent: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AuditRecord {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            username: row.try_get("username")?,
            action: row.try_get("action")?,
            resource_type: row.try_get("resource_type")?,
            resource_id: row.try_get("resource_id")?,
            detail: row.try_get("detail")?,
            before_data: row.try_get("before_data")?,
            after_data: row.try_get("after_data")?,
            ip_address: row.try_get("ip_address")?,
            user_agent: row.try_get("user_agent")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

/// 审计查询参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// 按用户ID过滤
    pub user_id: Option<String>,
    /// 按操作类型过滤
    pub action: Option<AuditAction>,
    /// 按资源类型过滤
    pub resource_type: Option<String>,
    /// 按资源ID过滤
    pub resource_id: Option<String>,
    /// 查询开始时间
    pub start_time: Option<DateTime<Utc>>,
    /// 查询结束时间
    pub end_time: Option<DateTime<Utc>>,
    /// 关键词搜索
    pub keyword: Option<String>,
    /// 页码
    pub page: Option<u64>,
    /// 每页记录数
    pub page_size: Option<u64>,
}

/// 审计查询结果。
#[derive(Debug, Clone, Serialize)]
pub struct AuditQueryResult {
    /// 结果记录列表
    pub records: Vec<AuditRecord>,
    /// 总记录数
    pub total: u64,
    /// 当前页码
    pub page: u64,
    /// 每页记录数
    pub page_size: u64,
}

/// 审计日志器。
pub struct AuditLogger {
    db_pool: sqlx::PgPool,
}

impl AuditLogger {
    /// 创建审计日志器。
    pub fn new(db_pool: sqlx::PgPool) -> Self {
        Self { db_pool }
    }

    /// 记录一条审计日志。
    ///
    /// # 参数
    /// * `user_id` - 操作用户ID
    /// * `username` - 操作用户名
    /// * `action` - 操作类型
    /// * `resource_type` - 资源类型
    /// * `resource_id` - 资源ID
    /// * `detail` - 操作详情
    /// * `before_data` - 变更前数据
    /// * `after_data` - 变更后数据
    /// * `ip_address` - 客户端IP
    /// * `user_agent` - 用户代理
    #[allow(clippy::too_many_arguments)]
    pub async fn log(
        &self,
        user_id: Option<String>,
        username: Option<String>,
        action: AuditAction,
        resource_type: String,
        resource_id: Option<String>,
        detail: String,
        before_data: Option<String>,
        after_data: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), String> {
        let id = uuid::Uuid::new_v4().to_string();
        let action_str = action.as_str();

        sqlx::query(
            r#"INSERT INTO audit_records
            (id, user_id, username, action, resource_type, resource_id, detail,
             before_data, after_data, ip_address, user_agent, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())"#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&username)
        .bind(&action_str)
        .bind(&resource_type)
        .bind(&resource_id)
        .bind(&detail)
        .bind(&before_data)
        .bind(&after_data)
        .bind(&ip_address)
        .bind(&user_agent)
        .execute(&self.db_pool)
        .await
        .map_err(|e| format!("审计日志写入失败: {}", e))?;

        Ok(())
    }

    /// 查询审计记录。
    pub async fn query(&self, params: AuditQuery) -> Result<AuditQueryResult, String> {
        let (page, page_size) =
            yma_pagination::parse_pagination_params(params.page, params.page_size);
        let offset = (page - 1) * page_size;

        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx = 1u32;

        if params.user_id.is_some() {
            conditions.push(format!("user_id = ${}", param_idx));
            param_idx += 1;
        }
        if params.action.is_some() {
            conditions.push(format!("action = ${}", param_idx));
            param_idx += 1;
        }
        if params.resource_type.is_some() {
            conditions.push(format!("resource_type = ${}", param_idx));
            param_idx += 1;
        }
        if params.resource_id.is_some() {
            conditions.push(format!("resource_id = ${}", param_idx));
            param_idx += 1;
        }
        if params.start_time.is_some() {
            conditions.push(format!("created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if params.end_time.is_some() {
            conditions.push(format!("created_at <= ${}", param_idx));
            param_idx += 1;
        }
        if params.keyword.is_some() {
            conditions.push(format!(
                "(detail ILIKE ${} OR resource_type ILIKE ${})",
                param_idx, param_idx
            ));
            let _ = param_idx;
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let count_sql = format!("SELECT COUNT(*) FROM audit_records {}", where_clause);
        let query_sql = format!(
            "SELECT * FROM audit_records {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
            where_clause, page_size, offset
        );

        let total: (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(count_sql.as_str())).fetch_one(&self.db_pool).await.map_err(|e| format!("查询失败: {}", e))?;

        let records: Vec<AuditRecord> = sqlx::query_as(sqlx::AssertSqlSafe(query_sql.as_str()))
            .fetch_all(&self.db_pool)
            .await
            .map_err(|e| format!("查询失败: {}", e))?;

        Ok(AuditQueryResult {
            records,
            total: total.0 as u64,
            page,
            page_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_as_str() {
        assert_eq!(AuditAction::Create.as_str(), "Create");
        assert_eq!(AuditAction::Update.as_str(), "Update");
        assert_eq!(AuditAction::Delete.as_str(), "Delete");
        assert_eq!(AuditAction::Login.as_str(), "Login");
        assert_eq!(AuditAction::Logout.as_str(), "Logout");
        assert_eq!(AuditAction::Export.as_str(), "Export");
        assert_eq!(AuditAction::ConfigChange.as_str(), "ConfigChange");
        assert_eq!(AuditAction::Other("Custom".to_string()).as_str(), "Custom");
    }

    #[test]
    fn test_audit_action_serialize() {
        let json = serde_json::to_string(&AuditAction::Create).unwrap();
        assert!(json.contains("Create"));
    }

    #[test]
    fn test_audit_query_default() {
        let query = AuditQuery {
            user_id: None,
            action: None,
            resource_type: None,
            resource_id: None,
            start_time: None,
            end_time: None,
            keyword: None,
            page: None,
            page_size: None,
        };
        assert!(query.user_id.is_none());
    }

    #[test]
    fn test_audit_query_with_filters() {
        let query = AuditQuery {
            user_id: Some("user-1".to_string()),
            action: Some(AuditAction::Login),
            resource_type: Some("auth".to_string()),
            resource_id: None,
            start_time: None,
            end_time: None,
            keyword: None,
            page: Some(1),
            page_size: Some(20),
        };
        assert_eq!(query.page, Some(1));
        assert_eq!(query.page_size, Some(20));
    }
}