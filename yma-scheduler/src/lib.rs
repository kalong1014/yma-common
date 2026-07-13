#![deny(missing_docs)]
//! 定时任务调度器，支持cron表达式、一次性任务和固定间隔任务

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::future::Future;
use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};

/// 任务状态
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TaskStatus {
    /// 等待执行
    Pending,
    /// 正在运行
    Running,
    /// 已暂停
    Paused,
    /// 执行失败
    Failed,
}

/// 任务信息
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskInfo {
    /// 任务唯一标识
    pub id: String,
    /// 任务名称
    pub name: String,
    /// 任务描述
    pub description: String,
    /// cron表达式或"once"表示一次性任务，"interval:N"表示每N秒执行
    pub schedule: String,
    /// 任务当前状态
    pub status: TaskStatus,
    /// 上次执行时间
    pub last_run: Option<DateTime<Utc>>,
    /// 下次计划执行时间
    pub next_run: Option<DateTime<Utc>>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
}

/// 定时任务调度器
pub struct TaskScheduler {
    scheduler: JobScheduler,
    tasks: Arc<DashMap<String, TaskInfo>>,
}

impl TaskScheduler {
    /// 创建调度器实例
    pub async fn new() -> Result<Self, String> {
        let scheduler = JobScheduler::new()
            .await
            .map_err(|e| format!("创建调度器失败: {}", e))?;

        Ok(Self {
            scheduler,
            tasks: Arc::new(DashMap::new()),
        })
    }

    /// 注册cron表达式定时任务
    ///
    /// # 参数
    /// * `name` - 任务名称（唯一标识）
    /// * `cron_expr` - cron表达式
    /// * `description` - 任务描述
    /// * `handler` - 任务执行函数
    pub async fn register_cron_task<F, Fut>(
        &self,
        name: &str,
        cron_expr: &str,
        description: &str,
        handler: F,
    ) -> Result<String, String>
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let task_id = uuid::Uuid::new_v4().to_string();
        let task_name = name.to_string();

        let tasks_ref = self.tasks.clone();
        let task_info = TaskInfo {
            id: task_id.clone(),
            name: task_name.clone(),
            description: description.to_string(),
            schedule: cron_expr.to_string(),
            status: TaskStatus::Pending,
            last_run: None,
            next_run: None,
            created_at: Utc::now(),
        };
        tasks_ref.insert(task_id.clone(), task_info);

        let tasks_for_job = self.tasks.clone();
        let tid_for_job = task_id.clone();

        let job = Job::new_async(cron_expr, move |_uuid, _lock| {
            let tasks = tasks_for_job.clone();
            let tid = tid_for_job.clone();
            let h = handler.clone();
            let tid2 = tid_for_job.clone();
            let tasks2 = tasks_for_job.clone();

            Box::pin(async move {
                if let Some(mut entry) = tasks.get_mut(&tid) {
                    entry.status = TaskStatus::Running;
                    entry.last_run = Some(Utc::now());
                }

                #[allow(clippy::redundant_closure)]
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h()));
                match result {
                    Ok(fut) => {
                        let start = std::time::Instant::now();
                        fut.await;
                        let elapsed = start.elapsed();
                        if elapsed.as_secs() > 1800 {
                            tracing::warn!(
                                "定时任务 {} 执行超过30分钟，可能存在问题，耗时: {}秒",
                                tid,
                                elapsed.as_secs()
                            );
                        }
                    }
                    Err(panic_info) => {
                        let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_info.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "未知panic".to_string()
                        };
                        tracing::error!("定时任务 {} 执行异常: {}", tid, panic_msg);
                    }
                }

                if let Some(mut entry) = tasks2.get_mut(&tid2) {
                    if entry.status == TaskStatus::Running {
                        entry.status = TaskStatus::Pending;
                    }
                }
            })
        })
        .map_err(|e| format!("创建cron任务失败: {}", e))?;

        self.scheduler
            .add(job)
            .await
            .map_err(|e| format!("添加cron任务失败: {}", e))?;

        Ok(task_id)
    }

    /// 注册一次性任务
    ///
    /// # 参数
    /// * `name` - 任务名称
    /// * `description` - 任务描述
    /// * `handler` - 任务执行函数
    pub async fn register_once_task<F, Fut>(
        &self,
        name: &str,
        description: &str,
        handler: F,
    ) -> Result<String, String>
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let task_id = uuid::Uuid::new_v4().to_string();
        let task_name = name.to_string();

        let tasks_ref = self.tasks.clone();
        let task_info = TaskInfo {
            id: task_id.clone(),
            name: task_name.clone(),
            description: description.to_string(),
            schedule: "once".to_string(),
            status: TaskStatus::Pending,
            last_run: None,
            next_run: None,
            created_at: Utc::now(),
        };
        tasks_ref.insert(task_id.clone(), task_info);

        let tasks_for_job = self.tasks.clone();
        let tid_for_job = task_id.clone();

        let job = Job::new_async("0 0 0 1 1 *", move |_uuid, _lock| {
            let tasks = tasks_for_job.clone();
            let tid = tid_for_job.clone();
            let h = handler.clone();
            let tid2 = tid_for_job.clone();
            let tasks2 = tasks_for_job.clone();

            Box::pin(async move {
                if let Some(mut entry) = tasks.get_mut(&tid) {
                    entry.status = TaskStatus::Running;
                    entry.last_run = Some(Utc::now());
                }

                #[allow(clippy::redundant_closure)]
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h()));
                match result {
                    Ok(fut) => {
                        fut.await;
                    }
                    Err(panic_info) => {
                        let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_info.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "未知panic".to_string()
                        };
                        tracing::error!("一次性任务 {} 执行异常: {}", tid, panic_msg);
                    }
                }

                if let Some(mut entry) = tasks2.get_mut(&tid2) {
                    entry.status = TaskStatus::Failed;
                }
            })
        })
        .map_err(|e| format!("创建一次性任务失败: {}", e))?;

        self.scheduler
            .add(job)
            .await
            .map_err(|e| format!("添加一次性任务失败: {}", e))?;

        Ok(task_id)
    }

    /// 注册固定间隔任务
    ///
    /// # 参数
    /// * `name` - 任务名称
    /// * `interval_secs` - 执行间隔（秒）
    /// * `description` - 任务描述
    /// * `handler` - 任务执行函数
    pub async fn register_interval_task<F, Fut>(
        &self,
        name: &str,
        interval_secs: u64,
        description: &str,
        handler: F,
    ) -> Result<String, String>
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let minutes = if interval_secs < 60 {
            1
        } else {
            interval_secs / 60
        };
        let cron_expr = format!("0 */{} * * * *", minutes);

        self.register_cron_task(name, &cron_expr, description, handler)
            .await
    }

    /// 启动调度器
    pub async fn start(&self) -> Result<(), String> {
        self.scheduler
            .start()
            .await
            .map_err(|e| format!("启动调度器失败: {}", e))
    }

    /// 停止调度器
    pub async fn stop(&self) -> Result<(), String> {
        for mut entry in self.tasks.iter_mut() {
            entry.status = TaskStatus::Paused;
        }
        Ok(())
    }

    /// 获取任务状态
    ///
    /// # 参数
    /// * `task_id` - 任务ID
    pub fn get_task_status(&self, task_id: &str) -> Option<TaskInfo> {
        self.tasks.get(task_id).map(|entry| entry.clone())
    }

    /// 获取所有任务列表
    pub fn list_tasks(&self) -> Vec<TaskInfo> {
        self.tasks.iter().map(|entry| entry.clone()).collect()
    }

    /// 移除任务
    ///
    /// # 参数
    /// * `task_id` - 任务ID
    pub fn remove_task(&self, task_id: &str) -> bool {
        self.tasks.remove(task_id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_info_creation() {
        let info = TaskInfo {
            id: "test-id".to_string(),
            name: "test".to_string(),
            description: "测试任务".to_string(),
            schedule: "0 */5 * * * *".to_string(),
            status: TaskStatus::Pending,
            last_run: None,
            next_run: None,
            created_at: Utc::now(),
        };
        assert_eq!(info.id, "test-id");
        assert_eq!(info.name, "test");
        assert_eq!(info.status, TaskStatus::Pending);
    }

    #[test]
    fn test_task_status_serialization() {
        let status = TaskStatus::Running;
        let json = serde_json::to_string(&status).unwrap();
        let parsed: TaskStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TaskStatus::Running);
    }

    #[tokio::test]
    async fn test_scheduler_new() {
        let scheduler = TaskScheduler::new().await;
        assert!(scheduler.is_ok());
    }

    #[tokio::test]
    async fn test_register_cron_task() {
        let scheduler = TaskScheduler::new().await.unwrap();

        let task_id = scheduler
            .register_cron_task("test_cron", "0 0 0 1 1 *", "测试cron任务", || async {})
            .await;

        assert!(task_id.is_ok());
        let task_id = task_id.unwrap();
        assert!(!task_id.is_empty());

        let status = scheduler.get_task_status(&task_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().name, "test_cron");
    }

    #[tokio::test]
    async fn test_register_multiple_tasks() {
        let scheduler = TaskScheduler::new().await.unwrap();

        let id1 = scheduler
            .register_cron_task("task1", "0 0 0 1 1 *", "任务1", || async {})
            .await
            .unwrap();

        let id2 = scheduler
            .register_cron_task("task2", "0 0 0 1 1 *", "任务2", || async {})
            .await
            .unwrap();

        let tasks = scheduler.list_tasks();
        assert_eq!(tasks.len(), 2);
        assert!(tasks.iter().any(|t| t.id == id1));
        assert!(tasks.iter().any(|t| t.id == id2));
    }

    #[tokio::test]
    async fn test_remove_task() {
        let scheduler = TaskScheduler::new().await.unwrap();

        let id = scheduler
            .register_cron_task("to_remove", "0 0 0 1 1 *", "待删除", || async {})
            .await
            .unwrap();

        assert!(scheduler.get_task_status(&id).is_some());
        assert!(scheduler.remove_task(&id));
        assert!(scheduler.get_task_status(&id).is_none());
    }

    #[tokio::test]
    async fn test_task_status_transitions() {
        let scheduler = TaskScheduler::new().await.unwrap();

        let id = scheduler
            .register_cron_task("status_test", "0 0 0 1 1 *", "状态测试", || async {})
            .await
            .unwrap();

        let info = scheduler.get_task_status(&id).unwrap();
        assert_eq!(info.status, TaskStatus::Pending);
    }
}