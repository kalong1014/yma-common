//! yma-logging 日志系统统一库
//!
//! 提供结构化日志输出的标准化接口，支持控制台输出和文件滚动写入
//! 版本锁定: 0.2.0

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use chrono::{Local, NaiveDate};
use tracing_subscriber::EnvFilter;

static LOGGER_INITIALIZED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// 日志级别
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// 日志配置
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: LogLevel,
    pub json_format: bool,
    pub file_path: Option<String>,
    pub max_file_size_mb: u64,
    pub retention_days: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            json_format: false,
            file_path: None,
            max_file_size_mb: 10,
            retention_days: 3,
        }
    }
}

/// 滚动文件追加器
/// 按天切割，单文件超过 max_file_size_mb 时创建序号文件
pub struct RollingFileAppender {
    prefix: String,
    dir: PathBuf,
    max_size: u64,
    #[allow(dead_code)]
    retention_days: u32,
    current_file: Arc<Mutex<PathBuf>>,
    current_size: Arc<AtomicU64>,
}

impl RollingFileAppender {
    pub fn new(prefix: String, dir: PathBuf, max_size_mb: u64, retention_days: u32) -> Self {
        fs::create_dir_all(&dir).ok();

        // 启动时清理过期日志
        Self::cleanup_old_logs(&dir, &prefix, retention_days);

        let today = Local::now().format("%Y-%m-%d").to_string();
        let current_file = Self::resolve_current_file(&dir, &prefix, &today);
        let current_size = Self::file_size(&current_file);

        Self {
            prefix,
            dir,
            max_size: max_size_mb * 1024 * 1024, // MB -> bytes
            retention_days,
            current_file: Arc::new(Mutex::new(current_file)),
            current_size: Arc::new(AtomicU64::new(current_size)),
        }
    }

    /// 获取文件大小
    fn file_size(path: &Path) -> u64 {
        fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    /// 解析当前应写入的文件路径
    fn resolve_current_file(dir: &Path, prefix: &str, today: &str) -> PathBuf {
        let mut index = 0;
        loop {
            let filename = if index == 0 {
                format!("{}-{}.log", prefix, today)
            } else {
                format!("{}-{}-{}.log", prefix, today, index)
            };
            let path = dir.join(&filename);
            if !path.exists() {
                return path;
            }
            let size = Self::file_size(&path);
            if size < 10 * 1024 * 1024 {
                // 假设默认10MB，实际由调用方控制
                return path;
            }
            index += 1;
        }
    }

    /// 清理过期日志文件
    fn cleanup_old_logs(dir: &Path, prefix: &str, retention_days: u32) {
        if retention_days == 0 {
            return;
        }

        let cutoff = Local::now().date_naive() - chrono::Days::new(retention_days as u64);

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    // 匹配格式: prefix-YYYY-MM-DD 或 prefix-YYYY-MM-DD-N
                    if name.starts_with(prefix) {
                        let date_part = name.trim_start_matches(prefix).trim_start_matches('-');
                        let date_str = date_part.split('-').take(3).collect::<Vec<_>>().join("-");

                        if let Ok(file_date) = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
                            if file_date < cutoff {
                                fs::remove_file(&path).ok();
                            }
                        }
                    }
                }
            }
        }
    }

    /// 检查是否需要滚动到新文件
    fn should_rollover(&self) -> bool {
        self.current_size.load(Ordering::Relaxed) >= self.max_size
    }

    /// 执行文件滚动
    fn rollover(&self) {
        let mut file_guard = self.current_file.lock().unwrap();
        let today = Local::now().format("%Y-%m-%d").to_string();
        let new_file = Self::resolve_current_file(&self.dir, &self.prefix, &today);
        *file_guard = new_file;
        self.current_size.store(0, Ordering::Relaxed);
    }

    /// 写入日志内容
    pub fn write(&self, content: &[u8]) -> std::io::Result<()> {
        if self.should_rollover() {
            self.rollover();
        }

        let path = self.current_file.lock().unwrap().clone();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        file.write_all(content)?;
        file.write_all(b"\n")?;
        file.flush()?;

        self.current_size.fetch_add(content.len() as u64 + 1, Ordering::Relaxed);
        Ok(())
    }

    /// 获取当前日志文件路径
    pub fn current_file(&self) -> PathBuf {
        self.current_file.lock().unwrap().clone()
    }
}

/// 日志写入器 (用于 tracing_subscriber)
pub struct FileLogWriter {
    appender: Arc<RollingFileAppender>,
}

impl FileLogWriter {
    pub fn new(appender: Arc<RollingFileAppender>) -> Self {
        Self { appender }
    }
}

impl std::io::Write for FileLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.appender.write(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 初始化日志系统
/// 支持控制台输出和文件滚动写入
pub fn init_logger(config: &LogConfig) -> Result<(), String> {
    if LOGGER_INITIALIZED.set(true).is_err() {
        return Ok(());
    }

    let filter = EnvFilter::try_from_env("RUST_LOG")
        .unwrap_or_else(|_| EnvFilter::new(config_level_str(config.level)));

    // 构建基础 subscriber
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true);

    if let Some(ref file_path) = config.file_path {
        // 文件日志模式
        let path = PathBuf::from(file_path);
        let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let prefix = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("app")
            .to_string();

        let appender = Arc::new(RollingFileAppender::new(
            prefix,
            dir,
            config.max_file_size_mb,
            config.retention_days,
        ));

        if config.json_format {
            subscriber
                .json()
                .with_writer({
                    let appender = appender.clone();
                    move || FileLogWriter::new(appender.clone())
                })
                .init();
        } else {
            subscriber
                .with_writer({
                    let appender = appender.clone();
                    move || FileLogWriter::new(appender.clone())
                })
                .init();
        }
    } else {
        // 仅控制台输出
        if config.json_format {
            subscriber.json().init();
        } else {
            subscriber.init();
        }
    }

    Ok(())
}

/// 手动触发日志清理 (删除超过 retention_days 的旧日志)
pub fn cleanup_logs(log_dir: &str, prefix: &str, retention_days: u32) {
    RollingFileAppender::cleanup_old_logs(Path::new(log_dir), prefix, retention_days);
}

fn config_level_str(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert!(matches!(config.level, LogLevel::Info));
        assert!(!config.json_format);
        assert_eq!(config.max_file_size_mb, 10);
        assert_eq!(config.retention_days, 3);
    }

    #[test]
    fn test_rolling_file_appender() {
        let temp_dir = TempDir::new().unwrap();
        let appender = RollingFileAppender::new(
            "test".to_string(),
            temp_dir.path().to_path_buf(),
            1, // 1MB
            7,
        );

        appender.write(b"test log line 1").unwrap();
        appender.write(b"test log line 2").unwrap();

        let current = appender.current_file();
        assert!(current.exists());

        let content = fs::read_to_string(&current).unwrap();
        assert!(content.contains("test log line 1"));
        assert!(content.contains("test log line 2"));
    }

    #[test]
    fn test_cleanup_old_logs() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        // 创建旧日志文件
        let old_file = dir.join("test-2020-01-01.log");
        fs::write(&old_file, "old log").unwrap();

        // 创建新日志文件
        let today = Local::now().format("%Y-%m-%d").to_string();
        let new_file = dir.join(format!("test-{}.log", today));
        fs::write(&new_file, "new log").unwrap();

        // 清理超过1天的日志
        RollingFileAppender::cleanup_old_logs(dir, "test", 1);

        assert!(!old_file.exists());
        assert!(new_file.exists());
    }
}