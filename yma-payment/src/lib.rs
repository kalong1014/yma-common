#![deny(missing_docs)]
//! 支付系统抽象层，提供支付订单、退款、对账的统一接口定义

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 支付方式
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentMethod {
    /// 微信支付
    WechatPay,
    /// 支付宝
    Alipay,
    /// 银行卡
    BankCard,
    /// 余额支付
    Balance,
    /// 其他
    Other(String),
}

/// 支付状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// 待支付
    Pending,
    /// 支付中
    Processing,
    /// 支付成功
    Success,
    /// 支付失败
    Failed,
    /// 已退款
    Refunded,
    /// 已关闭
    Closed,
}

/// 支付订单
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOrder {
    /// 订单ID（UUID v4）
    pub order_id: String,
    /// 商户订单号
    pub merchant_order_no: String,
    /// 支付金额（分）
    pub amount: i64,
    /// 货币类型，默认CNY
    pub currency: String,
    /// 支付方式
    pub method: PaymentMethod,
    /// 支付状态
    pub status: PaymentStatus,
    /// 商品描述
    pub description: String,
    /// 第三方交易号
    pub transaction_id: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 支付完成时间
    pub paid_at: Option<DateTime<Utc>>,
    /// 退款时间
    pub refunded_at: Option<DateTime<Utc>>,
}

/// 退款订单
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundOrder {
    /// 退款单ID
    pub refund_id: String,
    /// 原订单ID
    pub order_id: String,
    /// 退款金额（分）
    pub amount: i64,
    /// 退款原因
    pub reason: String,
    /// 退款状态
    pub status: PaymentStatus,
    /// 第三方退款号
    pub refund_transaction_id: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 完成时间
    pub completed_at: Option<DateTime<Utc>>,
}

/// 支付提供者抽象
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// 创建支付订单
    ///
    /// # 参数
    /// * `order` - 支付订单
    async fn create_order(&self, order: &PaymentOrder) -> Result<PaymentOrder, String>;

    /// 查询支付订单状态
    ///
    /// # 参数
    /// * `order_id` - 订单ID
    async fn query_order(&self, order_id: &str) -> Result<PaymentOrder, String>;

    /// 关闭支付订单
    ///
    /// # 参数
    /// * `order_id` - 订单ID
    async fn close_order(&self, order_id: &str) -> Result<PaymentOrder, String>;

    /// 申请退款
    ///
    /// # 参数
    /// * `order_id` - 原订单ID
    /// * `amount` - 退款金额（分）
    /// * `reason` - 退款原因
    async fn refund(
        &self,
        order_id: &str,
        amount: i64,
        reason: &str,
    ) -> Result<RefundOrder, String>;

    /// 查询退款状态
    ///
    /// # 参数
    /// * `refund_id` - 退款单ID
    async fn query_refund(&self, refund_id: &str) -> Result<RefundOrder, String>;

    /// 验证支付回调签名
    ///
    /// # 参数
    /// * `callback_data` - 回调数据
    async fn verify_callback(&self, callback_data: &str) -> Result<bool, String>;
}

/// 支付管理器
pub struct PaymentManager {
    providers: std::collections::HashMap<String, Box<dyn PaymentProvider>>,
}

impl PaymentManager {
    /// 创建支付管理器
    pub fn new() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
        }
    }

    /// 注册支付提供者
    ///
    /// # 参数
    /// * `name` - 提供者名称
    /// * `provider` - 支付提供者实例
    pub fn register_provider(&mut self, name: &str, provider: Box<dyn PaymentProvider>) {
        self.providers.insert(name.to_string(), provider);
    }

    /// 获取支付提供者
    ///
    /// # 参数
    /// * `name` - 提供者名称
    pub fn get_provider(&self, name: &str) -> Option<&dyn PaymentProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }

    /// 创建支付订单
    ///
    /// # 参数
    /// * `provider_name` - 提供者名称
    /// * `order` - 支付订单
    pub async fn create_order(
        &self,
        provider_name: &str,
        order: &PaymentOrder,
    ) -> Result<PaymentOrder, String> {
        let provider = self
            .providers
            .get(provider_name)
            .ok_or_else(|| format!("支付提供者 {} 未注册", provider_name))?;
        provider.create_order(order).await
    }

    /// 申请退款
    ///
    /// # 参数
    /// * `provider_name` - 提供者名称
    /// * `order_id` - 原订单ID
    /// * `amount` - 退款金额（分）
    /// * `reason` - 退款原因
    pub async fn refund(
        &self,
        provider_name: &str,
        order_id: &str,
        amount: i64,
        reason: &str,
    ) -> Result<RefundOrder, String> {
        let provider = self
            .providers
            .get(provider_name)
            .ok_or_else(|| format!("支付提供者 {} 未注册", provider_name))?;
        provider.refund(order_id, amount, reason).await
    }

    /// 获取所有已注册的提供者名称
    pub fn provider_names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}

impl Default for PaymentManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 内存支付提供者（测试用）
pub struct MemoryPaymentProvider {
    status: tokio::sync::RwLock<
        std::collections::HashMap<String, PaymentStatus>,
    >,
}

impl MemoryPaymentProvider {
    /// 创建内存支付提供者
    pub fn new() -> Self {
        Self {
            status: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemoryPaymentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PaymentProvider for MemoryPaymentProvider {
    async fn create_order(&self, order: &PaymentOrder) -> Result<PaymentOrder, String> {
        let mut created = order.clone();
        created.status = PaymentStatus::Pending;
        created.created_at = Utc::now();
        created.order_id = uuid::Uuid::new_v4().to_string();
        self.status
            .write()
            .await
            .insert(created.order_id.clone(), PaymentStatus::Pending);
        Ok(created)
    }

    async fn query_order(&self, order_id: &str) -> Result<PaymentOrder, String> {
        let status = self
            .status
            .read()
            .await
            .get(order_id)
            .cloned()
            .unwrap_or(PaymentStatus::Closed);

        Ok(PaymentOrder {
            order_id: order_id.to_string(),
            merchant_order_no: String::new(),
            amount: 0,
            currency: "CNY".to_string(),
            method: PaymentMethod::Balance,
            status,
            description: String::new(),
            transaction_id: None,
            created_at: Utc::now(),
            paid_at: None,
            refunded_at: None,
        })
    }

    async fn close_order(&self, order_id: &str) -> Result<PaymentOrder, String> {
        self.status
            .write()
            .await
            .insert(order_id.to_string(), PaymentStatus::Closed);
        Ok(PaymentOrder {
            order_id: order_id.to_string(),
            merchant_order_no: String::new(),
            amount: 0,
            currency: "CNY".to_string(),
            method: PaymentMethod::Balance,
            status: PaymentStatus::Closed,
            description: String::new(),
            transaction_id: None,
            created_at: Utc::now(),
            paid_at: None,
            refunded_at: None,
        })
    }

    async fn refund(
        &self,
        order_id: &str,
        amount: i64,
        reason: &str,
    ) -> Result<RefundOrder, String> {
        self.status
            .write()
            .await
            .insert(order_id.to_string(), PaymentStatus::Refunded);

        Ok(RefundOrder {
            refund_id: uuid::Uuid::new_v4().to_string(),
            order_id: order_id.to_string(),
            amount,
            reason: reason.to_string(),
            status: PaymentStatus::Success,
            refund_transaction_id: None,
            created_at: Utc::now(),
            completed_at: Some(Utc::now()),
        })
    }

    async fn query_refund(&self, refund_id: &str) -> Result<RefundOrder, String> {
        Ok(RefundOrder {
            refund_id: refund_id.to_string(),
            order_id: String::new(),
            amount: 0,
            reason: String::new(),
            status: PaymentStatus::Success,
            refund_transaction_id: None,
            created_at: Utc::now(),
            completed_at: None,
        })
    }

    async fn verify_callback(&self, _callback_data: &str) -> Result<bool, String> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_order_creation() {
        let order = PaymentOrder {
            order_id: uuid::Uuid::new_v4().to_string(),
            merchant_order_no: "ORD-001".to_string(),
            amount: 100,
            currency: "CNY".to_string(),
            method: PaymentMethod::WechatPay,
            status: PaymentStatus::Pending,
            description: "测试订单".to_string(),
            transaction_id: None,
            created_at: Utc::now(),
            paid_at: None,
            refunded_at: None,
        };

        assert_eq!(order.amount, 100);
        assert_eq!(order.currency, "CNY");
        assert_eq!(order.method, PaymentMethod::WechatPay);
    }

    #[test]
    fn test_payment_manager_new() {
        let manager = PaymentManager::new();
        assert!(manager.provider_names().is_empty());
    }

    #[test]
    fn test_payment_manager_register_provider() {
        let mut manager = PaymentManager::new();
        let provider = Box::new(MemoryPaymentProvider::new());
        manager.register_provider("memory", provider);
        assert!(manager.provider_names().contains(&"memory".to_string()));
        assert!(manager.get_provider("memory").is_some());
    }

    #[tokio::test]
    async fn test_memory_provider_create_order() {
        let provider = MemoryPaymentProvider::new();
        let order = PaymentOrder {
            order_id: String::new(),
            merchant_order_no: "TEST-001".to_string(),
            amount: 100,
            currency: "CNY".to_string(),
            method: PaymentMethod::Balance,
            status: PaymentStatus::Pending,
            description: "Test".to_string(),
            transaction_id: None,
            created_at: Utc::now(),
            paid_at: None,
            refunded_at: None,
        };

        let created = provider.create_order(&order).await.unwrap();
        assert_eq!(created.status, PaymentStatus::Pending);
        assert!(!created.order_id.is_empty());
    }

    #[tokio::test]
    async fn test_memory_provider_refund() {
        let provider = MemoryPaymentProvider::new();
        let refund = provider.refund("order-1", 50, "测试退款").await.unwrap();
        assert_eq!(refund.amount, 50);
        assert_eq!(refund.status, PaymentStatus::Success);
    }
}