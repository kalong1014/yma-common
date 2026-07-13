# yma-common

YMAIStation 公共基础库

**版本: 0.4.1**

## 项目结构

```
yma-common/
├── 已有核心模块 (8)
│   ├── yma-crypto/          # 国密算法统一库 (SM2/SM3/SM4/SHA)
│   ├── yma-auth/            # 认证授权统一库 (JWT/RBAC/MFA/Password)
│   ├── yma-sandbox/         # 安全沙箱 (Wasmtime 插件隔离)
│   ├── yma-advertising/     # 广告投放管理
│   ├── yma-config/          # 配置管理 (TOML/JSON)
│   ├── yma-events/          # 事件总线 (EventBus)
│   ├── yma-logging/         # 日志工具
│   └── yma-storage/         # 存储抽象层
├── 核心中间件层 (14)
│   ├── yma-api-response/    # 统一API响应格式
│   ├── yma-pagination/      # 分页工具
│   ├── yma-id/              # ID生成器 (UUID/Snowflake)
│   ├── yma-health/          # 健康检查端点
│   ├── yma-rate-limit/      # 限流模块
│   ├── yma-csrf/            # CSRF防护中间件
│   ├── yma-xss/             # XSS防护模块
│   ├── yma-sql-guard/       # SQL注入防护
│   ├── yma-security-headers/# 安全响应头管理
│   ├── yma-sensitive-filter/# 敏感词过滤器
│   ├── yma-validation/      # 通用验证器
│   ├── yma-data-masking/    # 敏感数据脱敏
│   ├── yma-api-version/     # API版本管理
│   └── yma-audit/           # 审计日志
├── 基础设施层 (8)
│   ├── yma-redis-pool/      # Redis连接池
│   ├── yma-email/           # 邮件发送服务
│   ├── yma-upload/          # 文件上传处理
│   ├── yma-scheduler/       # 定时任务调度器
│   ├── yma-websocket/       # WebSocket连接管理
│   ├── yma-migration/       # 数据库迁移管理
│   ├── yma-metrics/         # Prometheus指标
│   └── yma-search-client/   # Meilisearch客户端
├── 协议层 (2)
│   ├── yma-p2p/             # libp2p P2P抽象层
│   └── yma-ssh/             # SSH客户端模块
└── 域公共层 (3)
    ├── yma-llm/             # LLM客户端抽象
    ├── yma-social/          # 社交图抽象
    └── yma-payment/         # 支付与积分抽象
```

## 使用方式

在项目 `Cargo.toml` 中通过 git tag 锁定版本:

```toml
[dependencies]
yma-crypto = { git = "https://github.com/kalong1014/yma-common.git", tag = "v0.4.0" }
yma-auth   = { git = "https://github.com/kalong1014/yma-common.git", tag = "v0.4.0" }
```

## Crate 功能概览

### 已有核心模块

#### yma-crypto

| 模块 | 功能 | 说明 |
|------|------|------|
| `sm2` | SM2 密钥生成/签名/验签/加解密 | 国密非对称算法 |
| `sm3` | SM3 哈希/HMAC | 国密哈希算法 |
| `sm4` | SM4 对称加解密 (ECB/CBC/GCM) | 国密对称算法 |
| `sha` | SHA-256/SHA-512 哈希及 HMAC | 通用哈希算法 |
| `sm2_aead` | SM2 + SM4 混合加密 | 端到端加密 |
| `random` | 安全随机数生成 | `RandomGenerator`, `SecureRandom`, `Charset`, `generate_random_string` |
| `key_hierarchy` | 密钥层级管理 | `KeyManager` |
| `key_derivation` | 密钥派生 | `KeyDerivation` |
| `key_pool` | 密钥池 | `KeyPool` |
| `e2e` | 端到端加密器 | `E2eEncryptor` |

#### yma-auth

| 模块 | 功能 | 说明 |
|------|------|------|
| `password` | 密码哈希/验证 | `PasswordHasher`, `hash_password`(支持动态cost), `verify_password` |
| `jwt` | JWT 令牌管理 | `JwtService`（支持自定义TTL） |
| `rbac` | RBAC 权限控制 | `RbacEngine` |
| `mfa` | 多因素认证 | `MfaService` |
| `totp` | TOTP 验证 | `TotpService` |
| `session` | 会话管理 | `SessionStore` |
| `sso` | 第三方登录 (OAuth/OIDC) | `SsoManager` |
| `user` | 用户管理 | `User`, `UserStore` |
| `permission` | 权限管理 | `Permission`, `PermissionStore` |
| `role` | 角色管理 | `Role`, `RoleStore` |
| `api_key` | API 密钥 | `ApiKeyGenerator`, `ApiKeyStore` |
| `brute_force` | 暴力破解防护 | `BruteForceGuard` |
| `challenge` | 挑战验证 | `ChallengeManager` |
| `auth_service` | 认证服务 | `AuthService`（集成所有功能） |

### 核心中间件层

| crate | 功能 | 测试数 |
|-------|------|:------:|
| yma-api-response | 统一API响应格式，支持泛型/分页/错误码 | 8 |
| yma-pagination | 分页工具，参数校验与默认值修正 | 12 |
| yma-id | UUID v4/v7 及 Snowflake 分布式ID生成 | 2 |
| yma-health | 健康检查端点，支持DB/Redis检查项 | 5 |
| yma-rate-limit | 限流模块，支持内存/Redis后端 | 7 |
| yma-csrf | CSRF防护，一次性Token，常量时间比较 | 13 |
| yma-xss | XSS防护，HTML净化，JSON递归处理 | 11 |
| yma-sql-guard | SQL注入检测，四组正则规则 | 8 |
| yma-security-headers | 安全响应头管理，CSP/HSTS/Frame等 | 9 |
| yma-sensitive-filter | Aho-Corasick敏感词过滤，自实现自动机 | 13 |
| yma-validation | 通用验证器，邮箱/手机/身份证/密码等 | 20 |
| yma-data-masking | 敏感数据脱敏，手机/邮箱/身份证/银行卡 | 23 |
| yma-api-version | API版本管理，Active/Deprecated/Sunset | 9 |
| yma-audit | 审计日志，数据库存储与查询 | 4 |

### 基础设施层

| crate | 功能 | 测试数 |
|-------|------|:------:|
| yma-redis-pool | Redis连接池，基础操作/JSON/Hash/List/Set/PubSub | 3 |
| yma-email | 邮件发送服务，SMTP/TLS/批量发送 | 4 |
| yma-upload | 文件上传处理，校验/存储/MIME检测 | 9 |
| yma-scheduler | 定时任务调度器，Cron表达式 | 7 |
| yma-websocket | WebSocket连接管理，房间/心跳/广播 | 7 |
| yma-migration | 数据库迁移管理，版本追踪 | 7 |
| yma-metrics | Prometheus指标，Counter/Gauge/Histogram | 8 |
| yma-search-client | Meilisearch客户端，分页搜索 | 4 |

### 协议层

| crate | 功能 | 测试数 |
|-------|------|:------:|
| yma-p2p | libp2p P2P抽象层，节点发现/广播/消息 | 6 |
| yma-ssh | SSH客户端，密码/密钥认证，命令执行 | 4 |

### 域公共层

| crate | 功能 | 测试数 |
|-------|------|:------:|
| yma-llm | LLM客户端抽象，ChatCompletion/Stream | 4 |
| yma-social | 社交图抽象，关注/粉丝/拉黑/好友 | 7 |
| yma-payment | 支付抽象，订单/退款/回调验证 | 5 |

## 测试统计

- 总 crate 数: 35
- 总测试用例数: 385
- Clippy: 零警告 ✓
- 全部通过: ✓

## 变更日志

### v0.4.1 (2026-05-31)
- **技术栈升级**: rustc 1.89.0→1.96.0, sqlx 0.8.6→0.9.0, smcrypto 0.3→0.3.1, image 0.25→0.25.10, tokio 1.52.1→1.52.3
- **修复**: sqlx 0.9.0 API 迁移（SqlSafeStr/AssertSqlSafe、FromRow 手动实现）
- **新增**: yma-sandbox 编译与测试（rustc 升级后 wasmtime 43.0.2 兼容）
- **代码质量**: clippy 零警告（修复 6 处 clippy 警告）

### v0.4.0 (2026-05-31)
- **重大扩展**: 从 8 个 crate 扩展到 35 个 crate，新增 27 个共享模块
- **新增**: 核心中间件层 14 个 crate（API响应/分页/ID生成/健康检查/限流/CSRF/XSS/SQL注入/安全头/敏感词/验证/脱敏/版本管理/审计）
- **新增**: 基础设施层 8 个 crate（Redis/邮件/上传/调度/WebSocket/迁移/指标/搜索）
- **新增**: 协议层 2 个 crate（P2P/SSH）
- **新增**: 域公共层 3 个 crate（LLM/社交/支付）
- **修复**: yma-csrf DashMap 读写锁死锁问题
- **修复**: yma-config 测试中 YAML 格式断言与实际实现不一致
- **修复**: yma-logging 测试缺少 tempfile dev-dependency

### v0.3.4 (2026-05-22)
- **修复**: yma-crypto `digest` 版本升级至 0.11（统一 sm3/hmac 依赖），修复 SM3 HMAC `KeyInit` trait 未导入
- **修复**: yma-crypto `sh256`/`sha512` 链式调用编译错误（`Context::new(&SHA256)` 返回 `Context<Sha256>`，不可链式调用 `finish()` 后调用 `update()`）
- **修复**: yma-auth `middleware.rs` 缺失 `serde::Serialize` 导入导致 `AuthErrorResponse` derive 失败
- **修复**: yma-crypto `sm2.rs` 测试中 `pub_bytes` 未使用变量
- **修复**: yma-auth `middleware.rs` / `routes.rs` 移除未使用的导入
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.3 (2026-05-22)
- **修复**: `api_key.rs` API Key 预期长度从35修正为37（格式 `yma_{8}_{24}` 实际长度37）
- **修复**: `brute_force.rs` 测试 `is_locked`/`window_expiry` 需先调用 `check()` 触发锁定
- **修复**: `rbac.rs` `check_permission` 添加 `*` 通配符匹配支持
- **修复**: `session.rs` 测试会话限制正确触发
- **修复**: `mfa.rs` 测试读锁持有导致写锁死锁
- **修复**: `user.rs`/`role.rs`/`sso.rs` 测试借用检查编译错误
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.2 (2026-05-21)
- **修复**: `key_derivation.rs` pbkdf2_verify 使用正确的常量时间比较
- **修复**: `key_derivation.rs` hkdf_expand 按 RFC 5869 改用 HMAC-SHA256
- **修复**: 多处 clippy 警告（冗余闭包/冗余块/手动饱和减法）
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.1 (2026-05-21)
- **修复**: `Role::name()` 显示名重复（Level5/User 和 Level3/Guest）
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.0 (2026-05-21)
- **新增**: yma-crypto SHA-256/SHA-512 哈希及 HMAC
- **新增**: yma-crypto 随机字符串生成
- **新增**: yma-auth 支持动态 cost 的密码哈希
- **修复**: yma-auth web feature 升级至 axum 0.8
- **修复**: yma-events 订阅过滤逻辑未生效
- **修复**: 消除 digest crate 版本冲突
- **兼容**: 所有公开 API 保持向后兼容

### v0.2.0
- 初始稳定版本