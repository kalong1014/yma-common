//! yma-sandbox 插件沙箱统一库
//!
//! 提供 Wasmtime WASI 沙箱隔离执行环境
//! 版本锁定: 0.2.0

pub mod runtime;
pub mod quota;

pub use runtime::SandboxRuntime;
pub use quota::SandboxQuota;