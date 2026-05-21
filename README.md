# YMAIStation yma-common 公共基础库

这是 YMAIStation 项目的公共基础库，提供核心功能模块的通用实现。

## 项目结构

```
yma-common/
├── yma-crypto/       # 加密算法模块
├── yma-auth/         # 认证与授权模块
├── yma-sandbox/      # WASM 沙箱运行时
├── yma-advertising/  # 广告相关功能
├── yma-config/       # 配置管理
├── yma-events/       # 事件系统
├── yma-logging/      # 日志模块
└── yma-storage/      # 存储抽象层
```

## 模块说明

### yma-crypto
提供密码学相关功能，包括：
- SM2/SM3/SM4 国密算法实现
- 端到端加密
- 密钥派生与管理
- 随机数生成

### yma-auth
认证与授权模块，包括：
- JWT 令牌管理
- 密码哈希与验证
- 多因素认证 (MFA/TOTP)
- RBAC 权限控制
- API Key 管理
- 会话管理
- 暴力破解防护

### yma-sandbox
基于 Wasmtime 的 WASM 沙箱运行时：
- 安全的代码执行环境
- 资源配额管理
- 运行时隔离

### yma-config
配置管理模块：
- 统一配置加载
- 配置热更新

### yma-events
事件系统：
- 事件发布/订阅
- 事件处理

### yma-logging
日志模块：
- 基于 tracing 的日志实现
- 结构化日志输出

### yma-storage
存储抽象层：
- 统一存储接口
- 多种后端支持

## 技术栈

- **语言**: Rust 2021 Edition
- **构建工具**: Cargo
- **异步运行时**: Tokio
- **日志框架**: Tracing
- **序列化**: Serde
- **WASM 运行时**: Wasmtime

## 快速开始

### 构建项目

```bash
# 构建所有模块
cargo build --release

# 运行测试
cargo test --all
```

### 添加依赖

在 `Cargo.toml` 中添加需要的模块：

```toml
[dependencies]
yma-crypto = { path = "../yma-crypto" }
yma-auth = { path = "../yma-auth" }
```

## 许可证

MIT License