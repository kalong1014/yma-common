#![deny(missing_docs)]
//! SSH客户端模块，基于russh提供远程命令执行与文件传输能力

use async_trait::async_trait;
use russh::client;
use russh_keys::load_secret_key;
use ssh_key::PublicKey;
use std::path::Path;
use std::sync::Arc;

/// SSH认证方式
#[derive(Debug, Clone)]
pub enum SshAuthMethod {
    /// 密码认证
    Password {
        /// 用户名
        username: String,
        /// 密码
        password: String,
    },
    /// 密钥认证
    Key {
        /// 用户名
        username: String,
        /// 私钥文件路径
        key_path: String,
        /// 密钥密码短语，None表示无密码
        passphrase: Option<String>,
    },
}

/// SSH连接配置
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// 主机地址
    pub host: String,
    /// 端口号，默认22
    pub port: u16,
    /// 认证方式
    pub auth: SshAuthMethod,
    /// 连接超时秒数，默认30
    pub connect_timeout_secs: u64,
    /// 命令执行超时秒数，默认60
    pub command_timeout_secs: u64,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 22,
            auth: SshAuthMethod::Password {
                username: "root".to_string(),
                password: String::new(),
            },
            connect_timeout_secs: 30,
            command_timeout_secs: 60,
        }
    }
}

/// SSH命令执行结果
#[derive(Debug, Clone)]
pub struct SshCommandResult {
    /// 退出码
    pub exit_code: u32,
    /// 标准输出
    pub stdout: String,
    /// 标准错误
    pub stderr: String,
    /// 执行耗时毫秒
    pub duration_ms: u64,
}

/// 内部client handler
struct ClientHandler;

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// SSH客户端
pub struct SshClient {
    config: SshConfig,
}

impl SshClient {
    /// 创建SSH客户端
    pub fn new(config: SshConfig) -> Self {
        Self { config }
    }

    /// 连接到SSH服务器
    ///
    /// # 返回值
    /// 成功返回russh客户端会话句柄
    async fn connect(&self) -> Result<client::Handle<ClientHandler>, String> {
        let config = russh::client::Config::default();
        let config = Arc::new(config);

        let connect_future = russh::client::connect(
            config,
            (self.config.host.as_str(), self.config.port),
            ClientHandler,
        );

        let mut result = tokio::time::timeout(
            tokio::time::Duration::from_secs(self.config.connect_timeout_secs),
            connect_future,
        )
        .await
        .map_err(|_| "SSH连接超时".to_string())?
        .map_err(|e| format!("SSH连接失败: {}", e))?;

        let authenticated = match &self.config.auth {
            SshAuthMethod::Password { username, password } => {
                result
                    .authenticate_password(username, password)
                    .await
                    .map_err(|e| format!("密码认证失败: {}", e))?;
                true
            }
            SshAuthMethod::Key {
                username,
                key_path,
                passphrase,
            } => {
                let key_pair = load_secret_key(
                    Path::new(key_path),
                    passphrase.as_deref(),
                )
                .map_err(|e| format!("加载私钥失败: {}", e))?;

                result
                    .authenticate_publickey(username, Arc::new(key_pair))
                    .await
                    .map_err(|e| format!("密钥认证失败: {}", e))?;
                true
            }
        };

        if !authenticated {
            return Err("SSH认证失败".to_string());
        }

        Ok(result)
    }

    /// 执行远程命令
    ///
    /// # 参数
    /// * `command` - 要执行的命令
    ///
    /// # 返回值
    /// 命令执行结果（退出码、stdout、stderr）
    pub async fn execute(&self, command: &str) -> Result<SshCommandResult, String> {
        let handle = self.connect().await?;
        let start = std::time::Instant::now();

        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("打开会话通道失败: {}", e))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| format!("执行命令失败: {}", e))?;

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut exit_code = 0u32;

        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(self.config.command_timeout_secs);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err("命令执行超时".to_string());
            }

            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(russh::ChannelMsg::Data { data }) => {
                            stdout_buf.extend_from_slice(&data);
                        }
                        Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                            stderr_buf.extend_from_slice(&data);
                        }
                        Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                            exit_code = exit_status;
                        }
                        Some(russh::ChannelMsg::Eof) | None => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(SshCommandResult {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
            stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
            duration_ms,
        })
    }

    /// 测试连接是否可达
    ///
    /// # 返回值
    /// true表示连接和认证成功
    pub async fn test_connection(&self) -> Result<bool, String> {
        self.connect().await.map(|_| true)
    }
}

/// 错误类型
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// 连接错误
    #[error("连接失败: {0}")]
    Connection(String),
    /// 认证错误
    #[error("认证失败: {0}")]
    Authentication(String),
    /// 执行错误
    #[error("执行失败: {0}")]
    Execution(String),
    /// 超时错误
    #[error("操作超时")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_config_default() {
        let config = SshConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 22);
        assert_eq!(config.connect_timeout_secs, 30);
        assert_eq!(config.command_timeout_secs, 60);
    }

    #[test]
    fn test_ssh_auth_method_password() {
        let auth = SshAuthMethod::Password {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        match auth {
            SshAuthMethod::Password { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password, "secret");
            }
            _ => panic!("期望Password认证方式"),
        }
    }

    #[test]
    fn test_ssh_client_new() {
        let config = SshConfig {
            host: "192.168.1.1".to_string(),
            port: 2222,
            auth: SshAuthMethod::Password {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            connect_timeout_secs: 10,
            command_timeout_secs: 30,
        };
        let client = SshClient::new(config);
        assert_eq!(client.config.host, "192.168.1.1");
    }

    #[test]
    fn test_ssh_command_result() {
        let result = SshCommandResult {
            exit_code: 0,
            stdout: "output".to_string(),
            stderr: String::new(),
            duration_ms: 150,
        };
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "output");
        assert_eq!(result.duration_ms, 150);
    }
}