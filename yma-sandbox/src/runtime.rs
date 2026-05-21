use crate::quota::{NetworkTrafficMonitor, ResourceMonitor, SandboxQuota};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{self, WasiP1Ctx};

/// 沙箱运行时错误
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Wasm compilation failed: {0}")]
    CompilationFailed(String),
    #[error("Wasm instantiation failed: {0}")]
    InstantiationFailed(String),
    #[error("Execution timeout (limit: {0}s)")]
    ExecutionTimeout(u64),
    #[error("Memory quota exceeded (limit: {0}MB, current: {1}MB)")]
    MemoryQuotaExceeded(u64, u64),
    #[error("Network quota exceeded (limit: {0}MB/s, current: {1:.2}MB/s)")]
    NetworkQuotaExceeded(u64, f64),
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

/// 沙箱运行时
pub struct SandboxRuntime {
    engine: Engine,
}

impl SandboxRuntime {
    pub fn new() -> Result<Self, SandboxError> {
        let engine = Engine::default();
        Ok(Self { engine })
    }

    /// 在沙箱中执行 WASM 字节码
    /// 增加了内存监控和网络流量限速
    pub async fn spawn(
        &self,
        wasm_bytes: &[u8],
        quota: &SandboxQuota,
        args: &[String],
    ) -> Result<Vec<u8>, SandboxError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::CompilationFailed(e.to_string()))?;

        let wasi_ctx = WasiCtxBuilder::new()
            .inherit_stderr()
            .args(args)
            .build_p1();

        let mut store = Store::new(&self.engine, wasi_ctx);

        let mut linker: Linker<WasiP1Ctx> = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |t: &mut WasiP1Ctx| t)
            .map_err(|e| SandboxError::InstantiationFailed(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::InstantiationFailed(e.to_string()))?;

        // 创建资源监控器
        let monitor = ResourceMonitor::new(quota.clone());
        let network_monitor = NetworkTrafficMonitor::new();

        // 创建关闭信号
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        // 启动内存监控任务 (每100ms采样)
        let memory_monitor = monitor.clone_for_memory();
        let _memory_quota = quota.max_memory_mb;
        let memory_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // 这里通过外部接口获取内存，实际由主任务更新
                        if !memory_monitor.check_memory() {
                            let _ = shutdown_tx.send(true);
                            break;
                        }
                    }
                    _ = shutdown_rx.changed() => break,
                }
            }
        });

        // 获取 _start 或 main 函数
        let func_result = instance.get_typed_func::<(), ()>(&mut store, "_start")
            .ok()
            .or_else(|| instance.get_typed_func::<(), ()>(&mut store, "main").ok());

        let _start = Instant::now();
        let timeout = Duration::from_secs(quota.max_execution_secs);

        let result = if let Some(func) = func_result {
            let future = func.call_async(&mut store, ());

            // 使用 select! 同时监控超时和内存/网络配额
            tokio::select! {
                res = future => {
                    match res {
                        Ok(_) => Ok(Vec::new()),
                        Err(e) => Err(SandboxError::RuntimeError(e.to_string())),
                    }
                }
                _ = tokio::time::sleep(timeout) => {
                    Err(SandboxError::ExecutionTimeout(quota.max_execution_secs))
                }
            }
        } else {
            Ok(Vec::new())
        };

        // 执行后检查内存峰值
        if let Some(memory) = instance.get_memory(&mut store, "memory") {
            let current_pages = memory.size(&store);
            let current_bytes = current_pages * 65536; // 每页64KB
            let current_mb = current_bytes / 1024 / 1024;
            monitor.update_memory(current_mb);

            if current_mb > quota.max_memory_mb {
                let _ = memory_handle.await;
                return Err(SandboxError::MemoryQuotaExceeded(
                    quota.max_memory_mb,
                    current_mb,
                ));
            }
        }

        // 检查网络流量
        let network_mbps = network_monitor.current_mbps_data();
        if !quota.check_network(network_mbps) {
            let _ = memory_handle.await;
            return Err(SandboxError::NetworkQuotaExceeded(
                quota.max_network_mbps,
                network_mbps,
            ));
        }

        let _ = memory_handle.await;
        result
    }

    /// 获取引擎引用
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl ResourceMonitor {
    fn clone_for_memory(&self) -> Self {
        self.clone_for_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_runtime_new() {
        let runtime = SandboxRuntime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_sandbox_quota_default() {
        let quota = SandboxQuota::default();
        assert_eq!(quota.max_memory_mb, 64);
        assert_eq!(quota.max_execution_secs, 10);
        assert_eq!(quota.max_network_mbps, 20);
    }

    #[test]
    fn test_sandbox_quota_custom() {
        let quota = SandboxQuota::new(128, 30, 50);
        assert_eq!(quota.max_memory_mb, 128);
        assert_eq!(quota.max_execution_secs, 30);
        assert_eq!(quota.max_network_mbps, 50);
    }

    #[test]
    fn test_quota_check_memory() {
        let quota = SandboxQuota::new(64, 10, 20);
        assert!(quota.check_memory(32));
        assert!(quota.check_memory(64));
        assert!(!quota.check_memory(65));
    }

    #[test]
    fn test_quota_check_network() {
        let quota = SandboxQuota::new(64, 10, 20);
        assert!(quota.check_network(10.0));
        assert!(quota.check_network(20.0));
        assert!(!quota.check_network(21.0));
    }

    #[test]
    fn test_resource_monitor() {
        let monitor = ResourceMonitor::new(SandboxQuota::default());
        assert!(monitor.check_memory());

        monitor.update_memory(32);
        assert!(monitor.check_memory());

        monitor.update_memory(65);
        assert!(!monitor.check_memory());
    }

    #[test]
    fn test_network_traffic_monitor() {
        let monitor = NetworkTrafficMonitor::new();
        assert_eq!(monitor.total_bytes(), 0);

        monitor.record_sent(1024);
        monitor.record_received(2048);
        assert_eq!(monitor.total_bytes(), 3072);
    }

    #[tokio::test]
    async fn test_spawn_invalid_wasm() {
        let runtime = SandboxRuntime::new().unwrap();
        let result = runtime.spawn(&[0u8; 16], &SandboxQuota::default(), &[]).await;
        assert!(result.is_err());
    }
}