#![deny(missing_docs)]
//! 邮件发送服务，基于lettre提供SMTP邮件发送与批量发送功能

use lettre::{
    message::Mailbox,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

/// 邮件服务配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailConfig {
    /// SMTP服务器地址，如 "smtp.gmail.com"
    pub smtp_host: String,
    /// SMTP端口，默认587(STARTTLS)，可选465(TLS)，25(不安全)
    pub smtp_port: u16,
    /// SMTP认证用户名，通常为邮箱完整地址
    pub smtp_username: String,
    /// SMTP认证密码或应用专用密码
    pub smtp_password: String,
    /// 发件人显示名称，默认"YM System"
    pub from_name: String,
    /// 发件人邮箱地址
    pub from_email: String,
    /// 是否使用TLS加密，默认true
    pub use_tls: bool,
    /// 连接和发送超时秒数，默认30
    pub timeout_secs: u64,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_name: "YM System".to_string(),
            from_email: "noreply@example.com".to_string(),
            use_tls: true,
            timeout_secs: 30,
        }
    }
}

/// 邮件消息
#[derive(Debug, Clone)]
pub struct EmailMessage {
    /// 收件人邮箱列表，至少1个地址
    pub to: Vec<String>,
    /// 抄送邮箱列表，可为空
    pub cc: Vec<String>,
    /// 密送邮箱列表，可为空
    pub bcc: Vec<String>,
    /// 邮件主题
    pub subject: String,
    /// HTML格式正文
    pub body_html: Option<String>,
    /// 纯文本格式正文
    pub body_text: Option<String>,
}

impl EmailMessage {
    /// 创建简单文本邮件
    ///
    /// # 参数
    /// * `to` - 收件人邮箱地址
    /// * `subject` - 邮件主题
    /// * `body` - 纯文本正文
    pub fn new(to: impl Into<String>, subject: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            to: vec![to.into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: subject.into(),
            body_html: None,
            body_text: Some(body.into()),
        }
    }

    /// 添加HTML正文
    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        self.body_html = Some(html.into());
        self
    }

    /// 添加抄送列表
    pub fn with_cc(mut self, cc: Vec<String>) -> Self {
        self.cc = cc;
        self
    }

    /// 添加密送列表
    pub fn with_bcc(mut self, bcc: Vec<String>) -> Self {
        self.bcc = bcc;
        self
    }
}

/// 邮件发送服务
pub struct EmailService {
    config: EmailConfig,
}

impl EmailService {
    /// 创建邮件服务实例
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    /// 发送单封邮件
    ///
    /// # 参数
    /// * `message` - 邮件消息
    ///
    /// # 返回值
    /// 成功返回Ok，失败返回错误描述
    pub async fn send(&self, message: &EmailMessage) -> Result<(), String> {
        if message.to.is_empty() {
            return Err("收件人列表不能为空".to_string());
        }
        if message.body_text.is_none() && message.body_html.is_none() {
            return Err("邮件正文不能为空".to_string());
        }

        let from_mailbox = format!("{} <{}>", self.config.from_name, self.config.from_email)
            .parse::<Mailbox>()
            .map_err(|e| format!("发件人邮箱格式错误: {}", e))?;

        let mut msg_builder = Message::builder().from(from_mailbox).subject(&message.subject);

        for to_addr in &message.to {
            let mailbox = to_addr
                .parse::<Mailbox>()
                .map_err(|e| format!("收件人邮箱格式错误 '{}': {}", to_addr, e))?;
            msg_builder = msg_builder.to(mailbox);
        }

        for cc_addr in &message.cc {
            let mailbox = cc_addr
                .parse::<Mailbox>()
                .map_err(|e| format!("抄送邮箱格式错误 '{}': {}", cc_addr, e))?;
            msg_builder = msg_builder.cc(mailbox);
        }

        for bcc_addr in &message.bcc {
            let mailbox = bcc_addr
                .parse::<Mailbox>()
                .map_err(|e| format!("密送邮箱格式错误 '{}': {}", bcc_addr, e))?;
            msg_builder = msg_builder.bcc(mailbox);
        }

        let mut multipart = lettre::message::MultiPart::mixed().build();

        if let Some(ref text_body) = message.body_text {
            multipart = multipart.singlepart(
                lettre::message::SinglePart::builder()
                    .header(lettre::message::header::ContentType::TEXT_PLAIN)
                    .body(text_body.clone()),
            );
        }

        if let Some(ref html_body) = message.body_html {
            multipart = multipart.singlepart(
                lettre::message::SinglePart::builder()
                    .header(lettre::message::header::ContentType::TEXT_HTML)
                    .body(html_body.clone()),
            );
        }

        let email = msg_builder
            .multipart(multipart)
            .map_err(|e| format!("邮件构建失败: {}", e))?;

        let creds = Credentials::new(
            self.config.smtp_username.clone(),
            self.config.smtp_password.clone(),
        );

        let mailer = if self.config.use_tls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.smtp_host)
                .map_err(|e| format!("SMTP TLS连接创建失败: {}", e))?
                .port(self.config.smtp_port)
                .credentials(creds)
                .timeout(Some(std::time::Duration::from_secs(self.config.timeout_secs)))
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_host)
                .map_err(|e| format!("SMTP连接创建失败: {}", e))?
                .port(self.config.smtp_port)
                .credentials(creds)
                .timeout(Some(std::time::Duration::from_secs(self.config.timeout_secs)))
                .build()
        };

        mailer
            .send(email)
            .await
            .map_err(|e| format!("邮件发送失败: {}", e))?;

        Ok(())
    }

    /// 批量发送邮件
    ///
    /// # 参数
    /// * `messages` - 邮件消息列表
    ///
    /// # 返回值
    /// 元组 (成功数量, 失败错误列表)
    pub async fn send_batch(
        &self,
        messages: &[EmailMessage],
    ) -> Result<(usize, Vec<String>), String> {
        let mut success_count = 0usize;
        let mut errors = Vec::new();

        for msg in messages {
            match self.send(msg).await {
                Ok(()) => success_count += 1,
                Err(e) => errors.push(e),
            }
        }

        Ok((success_count, errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_message_new() {
        let msg = EmailMessage::new("test@example.com", "Subject", "Body text");
        assert_eq!(msg.to.len(), 1);
        assert_eq!(msg.to[0], "test@example.com");
        assert_eq!(msg.subject, "Subject");
        assert_eq!(msg.body_text, Some("Body text".to_string()));
        assert!(msg.body_html.is_none());
        assert!(msg.cc.is_empty());
        assert!(msg.bcc.is_empty());
    }

    #[test]
    fn test_email_message_with_html() {
        let msg = EmailMessage::new("test@example.com", "Subject", "Text")
            .with_html("<p>HTML</p>");
        assert_eq!(msg.body_html, Some("<p>HTML</p>".to_string()));
        assert_eq!(msg.body_text, Some("Text".to_string()));
    }

    #[test]
    fn test_email_message_with_cc_bcc() {
        let msg = EmailMessage::new("test@example.com", "Subject", "Text")
            .with_cc(vec!["cc@example.com".to_string()])
            .with_bcc(vec!["bcc@example.com".to_string()]);
        assert_eq!(msg.cc.len(), 1);
        assert_eq!(msg.bcc.len(), 1);
    }

    #[test]
    fn test_email_config_default() {
        let config = EmailConfig::default();
        assert_eq!(config.smtp_port, 587);
        assert!(config.use_tls);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.from_name, "YM System");
    }
}