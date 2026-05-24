# yma-common

YMAIStation 公共基础库

**版本: 0.3.2**

## 项目结构

```
yma-common/
├── yma-crypto/       # 国密算法统一库 (SM2/SM3/SM4/SHA)
├── yma-auth/         # 认证授权统一库 (JWT/RBAC/MFA/Password)
├── yma-sandbox/      # 安全沙箱 (Wasmtime 插件隔离)
├── yma-advertising/  # 广告投放管理
├── yma-config/       # 配置管理 (TOML/JSON)
├── yma-events/       # 事件总线 (EventBus)
├── yma-logging/      # 日志工具
└── yma-storage/      # 存储抽象层
```

## 使用方式

在项目 `Cargo.toml` 中通过 git tag 锁定版本:

```toml
[dependencies]
yma-crypto = { git = "https://github.com/kalong1014/yma-common.git", tag = "v0.3.3" }
yma-auth   = { git = "https://github.com/kalong1014/yma-common.git", tag = "v0.3.3" }
yma-sandbox = { git = "https://github.com/kalong1014/yma-common.git", tag = "v0.3.3" }
```

## Crate 功能概览

### yma-crypto

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

### yma-auth

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

## 变更日志

### v0.3.3 (2026-05-22)
- **修复**: `api_key.rs` API Key 预期长度从35修正为37（格式 `yma_{8}_{24}` 实际长度37）
- **修复**: `brute_force.rs` 测试 `is_locked`/`window_expiry` 需先调用 `check()` 触发锁定（`record_failure` 不自动设置 `locked_until`）
- **修复**: `rbac.rs` `check_permission` 添加 `*` 通配符匹配支持（`*:*` 权限应匹配任意资源/操作）
- **修复**: `session.rs` `test_session_max_per_user` 50个会话全部分配给同一用户以正确触发限制
- **修复**: `mfa.rs` 测试读锁持有导致 `verify_backup_code` 写锁死锁
- **修复**: `user.rs`/`role.rs`/`sso.rs` 测试4处借用检查编译错误
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.2 (2026-05-21)
- **修复**: `key_derivation.rs` `pbkdf2_verify` 使用正确的 `ring::pbkdf2::verify` 常量时间比较（原代码误用 hmac::verify 传入错误参数）
- **修复**: `key_derivation.rs` `hkdf_expand` 按 RFC 5869 改用 HMAC-SHA256（原代码错误使用裸 SHA-256 且忽略了 PRK）
- **修复**: `sm2_aead.rs`/`auth_service.rs` 3处冗余闭包 `.map_err(|e| T(e))` → `.map_err(T)`
- **修复**: `e2e.rs` 2处冗余 `{ let x = ...; x }` 块
- **修复**: `brute_force.rs` 手动饱和减法改为 `saturating_sub`
- **修复**: `runtime.rs` 手动 `if let Ok` 改为 `.ok().or_else()`
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.1 (2026-05-21)
- **修复**: `Role::name()` 显示名重复（Level5/User 和 Level3/Guest）
- **兼容**: 所有公开 API 保持向后兼容

### v0.3.0 (2026-05-21)
- **新增**: yma-crypto SHA-256/SHA-512 哈希及 HMAC (`sha` 模块)
- **新增**: yma-crypto 随机字符串生成 (`Charset` 枚举 + `generate_random_string`)
- **新增**: yma-auth 支持动态 cost 的 `hash_password`/`verify_password` 函数
- **修复**: yma-auth web feature 升级至 axum 0.8
- **修复**: yma-events `subscribe_filtered` 过滤逻辑未生效
- **修复**: 消除 `digest` crate 版本冲突（统一使用 digest 0.10，sha 模块改用 ring 实现）
- **清理**: 移除 yma-crypto 中 3 个空的 wrapper 存根文件及冗余的 sha2 依赖
- **兼容**: 所有公开 API 保持向后兼容

### v0.2.0
- 初始稳定版本