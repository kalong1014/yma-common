use serde::{Deserialize, Serialize};

/// 沙箱资源配额
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxQuota {
    /// 最大内存 (MB)
    pub max_memory_mb: u64,
    /// 最大执行时间 (秒)
    pub max_execution_secs: u64,
    /// 最大网络流量 (MB/s)
    pub max_network_mbps: u64,
}

impl Default for SandboxQuota {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_execution_secs: 10,
            max_network_mbps: 20,
        }
    }
}

impl SandboxQuota {
    pub fn new(max_memory_mb: u64, max_execution_secs: u64, max_network_mbps: u64) -> Self {
        Self {
            max_memory_mb,
            max_execution_secs,
            max_network_mbps,
        }
    }

    /// 检查当前内存使用是否超过配额
    pub fn check_memory(&self, current_memory_mb: u64) -> bool {
        current_memory_mb <= self.max_memory_mb
    }

    /// 检查当前网络流量是否超过配额
    pub fn check_network(&self, current_mbps: f64) -> bool {
        current_mbps <= self.max_network_mbps as f64
    }
}

/// 资源使用监控器
#[derive(Debug)]
pub struct ResourceMonitor {
    quota: SandboxQuota,
    start_time: std::time::Instant,
    peak_memory_mb: std::sync::atomic::AtomicU64,
    network_bytes: std::sync::atomic::AtomicU64,
    network_start: std::time::Instant,
}

impl ResourceMonitor {
    pub fn new(quota: SandboxQuota) -> Self {
        Self {
            quota,
            start_time: std::time::Instant::now(),
            peak_memory_mb: std::sync::atomic::AtomicU64::new(0),
            network_bytes: std::sync::atomic::AtomicU64::new(0),
            network_start: std::time::Instant::now(),
        }
    }

    /// 更新内存使用量 (MB)
    pub fn update_memory(&self, current_mb: u64) {
        let peak = self.peak_memory_mb.load(std::sync::atomic::Ordering::Relaxed);
        if current_mb > peak {
            self.peak_memory_mb.store(current_mb, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// 检查内存是否超限
    pub fn check_memory(&self) -> bool {
        let peak = self.peak_memory_mb.load(std::sync::atomic::Ordering::Relaxed);
        self.quota.check_memory(peak)
    }

    /// 记录网络流量字节数
    pub fn record_network_bytes(&self, bytes: u64) {
        self.network_bytes.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// 获取当前网络速率 (MB/s)
    pub fn current_network_mbps(&self) -> f64 {
        let bytes = self.network_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = self.network_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (bytes as f64 / 1024.0 / 1024.0) / elapsed
        } else {
            0.0
        }
    }

    /// 检查网络速率是否超限
    pub fn check_network(&self) -> bool {
        self.quota.check_network(self.current_network_mbps())
    }

    /// 获取峰值内存 (MB)
    pub fn peak_memory_mb(&self) -> u64 {
        self.peak_memory_mb.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 获取已执行时间 (秒)
    pub fn elapsed_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// 创建用于独立监控任务的克隆副本
    pub fn clone_for_metrics(&self) -> Self {
        Self {
            quota: self.quota.clone(),
            start_time: std::time::Instant::now(),
            peak_memory_mb: std::sync::atomic::AtomicU64::new(
                self.peak_memory_mb.load(std::sync::atomic::Ordering::Relaxed),
            ),
            network_bytes: std::sync::atomic::AtomicU64::new(0),
            network_start: std::time::Instant::now(),
        }
    }
}

/// 网络流量监控器 (用于WASI网络调用拦截)
#[derive(Debug, Clone)]
pub struct NetworkTrafficMonitor {
    bytes_sent: std::sync::Arc<std::sync::atomic::AtomicU64>,
    bytes_received: std::sync::Arc<std::sync::atomic::AtomicU64>,
    start_time: std::time::Instant,
}

impl NetworkTrafficMonitor {
    pub fn new() -> Self {
        Self {
            bytes_sent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            bytes_received: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn total_bytes(&self) -> u64 {
        let sent = self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
        let received = self.bytes_received.load(std::sync::atomic::Ordering::Relaxed);
        sent + received
    }

    /// 计算当前 Mbps
    pub fn current_mbps(&self) -> f64 {
        let total = self.total_bytes();
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (total as f64 * 8.0 / 1024.0 / 1024.0) / elapsed
        } else {
            0.0
        }
    }

    /// 计算当前 MB/s
    pub fn current_mbps_data(&self) -> f64 {
        let total = self.total_bytes();
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (total as f64 / 1024.0 / 1024.0) / elapsed
        } else {
            0.0
        }
    }
}

impl Default for NetworkTrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}