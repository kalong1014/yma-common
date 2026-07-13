#![deny(missing_docs)]
//! 数据库迁移管理，支持SQL迁移文件加载、版本追踪与应用

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::path::PathBuf;

/// 迁移记录
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationRecord {
    /// 迁移版本号
    pub version: i64,
    /// 迁移名称
    pub name: String,
    /// 迁移描述
    pub description: String,
    /// 应用时间
    pub applied_at: Option<DateTime<Utc>>,
    /// 是否已应用
    pub applied: bool,
    /// 执行耗时毫秒
    pub duration_ms: Option<u64>,
}

/// 迁移配置
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// SQL迁移文件目录路径
    pub migrations_dir: PathBuf,
    /// 迁移记录表名，默认"_migrations"
    pub table_name: String,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            migrations_dir: PathBuf::from("./migrations"),
            table_name: "_migrations".to_string(),
        }
    }
}

/// 迁移管理器
pub struct MigrationManager {
    config: MigrationConfig,
    records: DashMap<i64, MigrationRecord>,
}

impl MigrationManager {
    /// 创建迁移管理器
    pub fn new(config: MigrationConfig) -> Self {
        Self {
            config,
            records: DashMap::new(),
        }
    }

    /// 从迁移目录加载所有SQL迁移文件
    ///
    /// 迁移文件命名格式: {version}_{name}.sql
    /// 例如: 001_initial_schema.sql, 002_add_users_table.sql
    ///
    /// # 返回值
    /// 成功加载的迁移记录数量
    pub async fn load_migrations(&self) -> Result<usize, String> {
        let dir = &self.config.migrations_dir;

        if !dir.exists() {
            return Ok(0);
        }

        let mut entries = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| format!("读取迁移目录失败: {}", e))?;

        let mut count = 0usize;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| format!("遍历迁移目录失败: {}", e))?
        {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sql") {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    if let Some((version_str, migration_name)) = name.split_once('_') {
                        if let Ok(version) = version_str.parse::<i64>() {
                            let record = MigrationRecord {
                                version,
                                name: migration_name.to_string(),
                                description: format!("迁移: {}", migration_name.replace('_', " ")),
                                applied_at: None,
                                applied: false,
                                duration_ms: None,
                            };
                            self.records.insert(version, record);
                            count += 1;
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// 获取迁移文件完整路径
    ///
    /// # 参数
    /// * `version` - 迁移版本号
    /// * `name` - 迁移名称
    fn migration_file_path(&self, version: i64, name: &str) -> PathBuf {
        self.config
            .migrations_dir
            .join(format!("{:03}_{}.sql", version, name))
    }

    /// 读取迁移SQL内容
    ///
    /// # 参数
    /// * `version` - 迁移版本号
    /// * `name` - 迁移名称
    async fn read_migration_sql(&self, version: i64, name: &str) -> Result<String, String> {
        let path = self.migration_file_path(version, name);
        tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| format!("读取迁移文件 {} 失败: {}", path.display(), e))
    }

    /// 应用指定迁移
    ///
    /// # 参数
    /// * `version` - 迁移版本号
    /// * `pool` - 数据库连接池
    pub async fn apply_migration(
        &self,
        version: i64,
        pool: &sqlx::PgPool,
    ) -> Result<(), String> {
        let record = self
            .records
            .get(&version)
            .ok_or_else(|| format!("未找到迁移版本 {}", version))?;

        if record.applied {
            return Err(format!("迁移 {} 已应用，跳过", version));
        }

        let sql = self.read_migration_sql(version, &record.name).await?;
        let start = std::time::Instant::now();

        let mut tx = pool
            .begin()
            .await
            .map_err(|e| format!("开始事务失败: {}", e))?;

        sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("执行迁移SQL失败: {}", e))?;

        let insert_sql = format!(
            "INSERT INTO {} (version, name, description, applied_at, duration_ms) VALUES ($1, $2, $3, NOW(), $4)",
            self.config.table_name
        );
        sqlx::query(sqlx::AssertSqlSafe(insert_sql.as_str()))
            .bind(version as i32)
            .bind(&record.name)
            .bind(&record.description)
            .bind(start.elapsed().as_millis() as i32)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("记录迁移状态失败: {}", e))?;

        tx.commit()
            .await
            .map_err(|e| format!("提交事务失败: {}", e))?;

        let duration_ms = start.elapsed().as_millis() as u64;
        if let Some(mut entry) = self.records.get_mut(&version) {
            entry.applied = true;
            entry.applied_at = Some(Utc::now());
            entry.duration_ms = Some(duration_ms);
        }

        Ok(())
    }

    /// 应用所有未应用的迁移
    ///
    /// # 参数
    /// * `pool` - 数据库连接池
    ///
    /// # 返回值
    /// 成功应用的迁移数量
    pub async fn apply_all(&self, pool: &sqlx::PgPool) -> Result<usize, String> {
        let mut versions: Vec<i64> = self
            .records
            .iter()
            .filter(|r| !r.applied)
            .map(|r| r.version)
            .collect();
        versions.sort();

        let mut applied = 0usize;
        for version in versions {
            self.apply_migration(version, pool).await?;
            applied += 1;
        }

        Ok(applied)
    }

    /// 获取迁移状态列表
    pub fn get_migration_status(&self) -> Vec<MigrationRecord> {
        let mut records: Vec<MigrationRecord> =
            self.records.iter().map(|r| r.clone()).collect();
        records.sort_by_key(|r| r.version);
        records
    }

    /// 获取指定版本的迁移记录
    ///
    /// # 参数
    /// * `version` - 迁移版本号
    pub fn get_migration(&self, version: i64) -> Option<MigrationRecord> {
        self.records.get(&version).map(|r| r.clone())
    }

    /// 获取下一个待应用的迁移版本
    pub fn next_pending_version(&self) -> Option<i64> {
        self.records
            .iter()
            .filter(|r| !r.applied)
            .map(|r| r.version)
            .min()
    }

    /// 获取当前已应用的最高版本
    pub fn current_version(&self) -> Option<i64> {
        self.records
            .iter()
            .filter(|r| r.applied)
            .map(|r| r.version)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_config_default() {
        let config = MigrationConfig::default();
        assert_eq!(config.table_name, "_migrations");
        assert_eq!(config.migrations_dir, PathBuf::from("./migrations"));
    }

    #[test]
    fn test_migration_record_creation() {
        let record = MigrationRecord {
            version: 1,
            name: "initial".to_string(),
            description: "初始迁移".to_string(),
            applied_at: None,
            applied: false,
            duration_ms: None,
        };
        assert_eq!(record.version, 1);
        assert!(!record.applied);
        assert_eq!(record.name, "initial");
    }

    #[test]
    fn test_migration_manager_new() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);
        assert!(manager.get_migration_status().is_empty());
    }

    #[test]
    fn test_next_pending_version() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);

        manager.records.insert(
            1,
            MigrationRecord {
                version: 1,
                name: "first".to_string(),
                description: "第一".to_string(),
                applied_at: Some(Utc::now()),
                applied: true,
                duration_ms: Some(100),
            },
        );

        manager.records.insert(
            2,
            MigrationRecord {
                version: 2,
                name: "second".to_string(),
                description: "第二".to_string(),
                applied_at: None,
                applied: false,
                duration_ms: None,
            },
        );

        assert_eq!(manager.next_pending_version(), Some(2));
        assert_eq!(manager.current_version(), Some(1));
    }

    #[test]
    fn test_get_migration_not_found() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);
        assert!(manager.get_migration(999).is_none());
    }

    #[tokio::test]
    async fn test_load_migrations_empty_dir() {
        let temp_dir = std::env::temp_dir().join("yma_migration_test_empty");
        let _ = std::fs::create_dir_all(&temp_dir);

        let config = MigrationConfig {
            migrations_dir: temp_dir.clone(),
            table_name: "_migrations".to_string(),
        };
        let manager = MigrationManager::new(config);
        let count = manager.load_migrations().await.unwrap();
        assert_eq!(count, 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_load_migrations_with_files() {
        let temp_dir = std::env::temp_dir().join("yma_migration_test");
        let _ = std::fs::create_dir_all(&temp_dir);

        std::fs::write(temp_dir.join("001_initial_schema.sql"), "CREATE TABLE test (id SERIAL PRIMARY KEY);").unwrap();
        std::fs::write(temp_dir.join("002_add_users.sql"), "ALTER TABLE test ADD COLUMN name TEXT;").unwrap();
        std::fs::write(temp_dir.join("readme.txt"), "not a migration").unwrap();

        let config = MigrationConfig {
            migrations_dir: temp_dir.clone(),
            table_name: "_migrations".to_string(),
        };
        let manager = MigrationManager::new(config);
        let count = manager.load_migrations().await.unwrap();
        assert_eq!(count, 2);

        let status = manager.get_migration_status();
        assert_eq!(status.len(), 2);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}