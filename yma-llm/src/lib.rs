#![deny(missing_docs)]
//! LLM客户端抽象层，提供大模型对话补全、流式输出、多模型切换的统一接口

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// 对话角色
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatRole {
    /// 系统提示
    System,
    /// 用户消息
    User,
    /// 助手回复
    Assistant,
}

/// 对话消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// 角色
    pub role: ChatRole,
    /// 消息内容
    pub content: String,
    /// 消息名称（可选，用于函数调用）
    pub name: Option<String>,
}

impl ChatMessage {
    /// 创建系统消息
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
            name: None,
        }
    }

    /// 创建用户消息
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
            name: None,
        }
    }

    /// 创建助手消息
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.into(),
            name: None,
        }
    }
}

/// LLM模型配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// API端点URL
    pub api_url: String,
    /// API密钥
    pub api_key: String,
    /// 模型名称
    pub model: String,
    /// 温度参数（0.0-2.0），默认0.7
    pub temperature: f64,
    /// 最大输出token数，默认4096
    pub max_tokens: u32,
    /// 请求超时秒数，默认60
    pub timeout_secs: u64,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.openai.com/v1/chat/completions".to_string(),
            api_key: String::new(),
            model: "gpt-4".to_string(),
            temperature: 0.7,
            max_tokens: 4096,
            timeout_secs: 60,
        }
    }
}

/// 对话补全请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    /// 消息列表
    pub messages: Vec<ChatMessage>,
    /// 是否流式输出
    pub stream: bool,
    /// 温度参数覆盖（None则使用配置默认值）
    pub temperature: Option<f64>,
    /// 最大token数覆盖（None则使用配置默认值）
    pub max_tokens: Option<u32>,
}

impl ChatCompletionRequest {
    /// 创建简单请求
    pub fn new(messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            stream: false,
            temperature: None,
            max_tokens: None,
        }
    }

    /// 启用流式输出
    pub fn with_stream(mut self) -> Self {
        self.stream = true;
        self
    }

    /// 设置温度
    pub fn with_temperature(mut self, temp: f64) -> Self {
        self.temperature = Some(temp);
        self
    }

    /// 设置最大token
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }
}

/// 对话补全响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    /// 消息ID
    pub id: String,
    /// 模型名称
    pub model: String,
    /// 回复消息
    pub message: ChatMessage,
    /// 完成原因（stop, length, etc.）
    pub finish_reason: Option<String>,
    /// 使用的token数
    pub usage: Option<UsageInfo>,
    /// 耗时毫秒
    pub duration_ms: u64,
}

/// Token使用信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageInfo {
    /// 提示token数
    pub prompt_tokens: u32,
    /// 完成token数
    pub completion_tokens: u32,
    /// 总token数
    pub total_tokens: u32,
}

/// 流式输出块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    /// 增量内容
    pub content: String,
    /// 完成原因（如果是最后一个chunk）
    pub finish_reason: Option<String>,
    /// 当前chunk的索引
    pub index: u32,
}

/// LLM提供者抽象
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// 对话补全（非流式）
    ///
    /// # 参数
    /// * `request` - 对话补全请求
    async fn chat_completion(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, String>;

    /// 对话补全（流式输出）
    ///
    /// # 参数
    /// * `request` - 对话补全请求
    ///
    /// # 返回值
    /// 流式chunk接收器
    async fn chat_completion_stream(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<
        tokio::sync::mpsc::Receiver<Result<StreamChunk, String>>,
        String,
    >;

    /// 获取模型列表
    async fn list_models(&self) -> Result<Vec<String>, String>;

    /// 健康检查
    async fn health_check(&self) -> Result<bool, String>;
}

/// LLM客户端管理器
pub struct LlmClientManager {
    providers: std::collections::HashMap<String, Box<dyn LlmProvider>>,
    default_provider: Option<String>,
}

impl LlmClientManager {
    /// 创建LLM客户端管理器
    pub fn new() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
            default_provider: None,
        }
    }

    /// 注册LLM提供者
    ///
    /// # 参数
    /// * `name` - 提供者名称
    /// * `provider` - LLM提供者实例
    /// * `is_default` - 是否设为默认提供者
    pub fn register_provider(
        &mut self,
        name: &str,
        provider: Box<dyn LlmProvider>,
        is_default: bool,
    ) {
        self.providers.insert(name.to_string(), provider);
        if is_default || self.default_provider.is_none() {
            self.default_provider = Some(name.to_string());
        }
    }

    /// 获取指定提供者
    pub fn get_provider(&self, name: &str) -> Option<&dyn LlmProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }

    /// 获取默认提供者
    pub fn default_provider(&self) -> Option<&dyn LlmProvider> {
        self.default_provider
            .as_ref()
            .and_then(|name| self.providers.get(name).map(|p| p.as_ref()))
    }

    /// 使用默认提供者进行对话补全
    pub async fn chat(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, String> {
        let provider = self
            .default_provider()
            .ok_or("没有配置默认LLM提供者")?;
        provider.chat_completion(request).await
    }

    /// 获取所有已注册的提供者名称
    pub fn provider_names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}

impl Default for LlmClientManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_creation() {
        let sys_msg = ChatMessage::system("You are helpful");
        assert_eq!(sys_msg.role, ChatRole::System);
        assert_eq!(sys_msg.content, "You are helpful");

        let user_msg = ChatMessage::user("Hello");
        assert_eq!(user_msg.role, ChatRole::User);

        let asst_msg = ChatMessage::assistant("Hi there");
        assert_eq!(asst_msg.role, ChatRole::Assistant);
    }

    #[test]
    fn test_chat_completion_request() {
        let request = ChatCompletionRequest::new(vec![
            ChatMessage::user("Hello"),
        ])
        .with_stream()
        .with_temperature(0.5)
        .with_max_tokens(2048);

        assert!(request.stream);
        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.max_tokens, Some(2048));
    }

    #[test]
    fn test_llm_config_default() {
        let config = LlmConfig::default();
        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.temperature, 0.7);
        assert_eq!(config.max_tokens, 4096);
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_llm_client_manager_new() {
        let manager = LlmClientManager::new();
        assert!(manager.provider_names().is_empty());
        assert!(manager.default_provider().is_none());
    }
}