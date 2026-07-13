#![deny(missing_docs)]
//! P2P网络通信模块，提供节点消息传递与广播能力

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// P2P节点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// 节点唯一标识
    pub id: String,
    /// 节点地址
    pub addr: SocketAddr,
    /// 节点名称
    pub name: String,
}

/// P2P消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMessage {
    /// 消息ID（UUID v4）
    pub message_id: String,
    /// 发送者ID
    pub sender_id: String,
    /// 接收者ID（None表示广播）
    pub receiver_id: Option<String>,
    /// 消息类型
    pub msg_type: String,
    /// 消息负载（JSON序列化）
    pub payload: String,
    /// 时间戳毫秒
    pub timestamp_ms: i64,
}

/// P2P网络事件
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// 新节点连接
    PeerConnected(PeerInfo),
    /// 节点断开
    PeerDisconnected(String),
    /// 收到直接消息
    DirectMessage(P2pMessage),
    /// 收到广播消息
    BroadcastMessage(P2pMessage),
}

/// P2P网络配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// 本地监听地址，默认 "0.0.0.0:0"
    pub listen_addr: String,
    /// 本节点标识名称
    pub node_name: String,
    /// 引导节点地址列表
    pub bootstrap_nodes: Vec<String>,
    /// 心跳间隔秒数，默认15
    pub heartbeat_interval_secs: u64,
    /// 事件通道缓冲区大小，默认256
    pub event_buffer_size: usize,
    /// 最大已连接节点数，默认50
    pub max_peers: usize,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".to_string(),
            node_name: "yma-node".to_string(),
            bootstrap_nodes: Vec::new(),
            heartbeat_interval_secs: 15,
            event_buffer_size: 256,
            max_peers: 50,
        }
    }
}

/// P2P节点
pub struct P2pNode {
    config: P2pConfig,
    node_id: String,
    event_tx: mpsc::Sender<P2pEvent>,
    event_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<P2pEvent>>>,
    connected_peers: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

impl P2pNode {
    /// 创建P2P节点
    ///
    /// # 参数
    /// * `config` - P2P配置
    pub fn new(config: P2pConfig) -> Self {
        let node_id = uuid::Uuid::new_v4().to_string();
        let (event_tx, event_rx) = mpsc::channel(config.event_buffer_size);

        Self {
            config,
            node_id,
            event_tx,
            event_rx: Arc::new(tokio::sync::Mutex::new(event_rx)),
            connected_peers: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        }
    }

    /// 获取本地节点ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// 获取事件接收器
    pub fn event_receiver(&self) -> Arc<tokio::sync::Mutex<mpsc::Receiver<P2pEvent>>> {
        self.event_rx.clone()
    }

    /// 获取已连接节点ID列表
    pub async fn connected_peers(&self) -> Vec<String> {
        self.connected_peers.lock().await.iter().cloned().collect()
    }

    /// 获取已连接节点数量
    pub async fn peer_count(&self) -> usize {
        self.connected_peers.lock().await.len()
    }

    /// 添加已连接节点
    pub async fn add_peer(&self, peer_id: String) {
        self.connected_peers.lock().await.insert(peer_id.clone());
        let _ = self
            .event_tx
            .send(P2pEvent::PeerConnected(PeerInfo {
                id: peer_id,
                addr: "0.0.0.0:0".parse().unwrap(),
                name: String::new(),
            }))
            .await;
    }

    /// 移除已连接节点
    pub async fn remove_peer(&self, peer_id: &str) {
        self.connected_peers.lock().await.remove(peer_id);
        let _ = self
            .event_tx
            .send(P2pEvent::PeerDisconnected(peer_id.to_string()))
            .await;
    }

    /// 发送消息到指定节点
    ///
    /// # 参数
    /// * `receiver_id` - 接收者节点ID
    /// * `msg_type` - 消息类型
    /// * `payload` - 消息负载（JSON序列化）
    pub async fn send_message(
        &self,
        receiver_id: &str,
        msg_type: &str,
        payload: &str,
    ) -> Result<(), String> {
        let msg = P2pMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            sender_id: self.node_id.clone(),
            receiver_id: Some(receiver_id.to_string()),
            msg_type: msg_type.to_string(),
            payload: payload.to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };
        let _ = self.event_tx.send(P2pEvent::DirectMessage(msg)).await;
        Ok(())
    }

    /// 广播消息到所有已连接节点
    ///
    /// # 参数
    /// * `msg_type` - 消息类型
    /// * `payload` - 消息负载
    pub async fn broadcast(&self, msg_type: &str, payload: &str) -> Result<(), String> {
        let msg = P2pMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            sender_id: self.node_id.clone(),
            receiver_id: None,
            msg_type: msg_type.to_string(),
            payload: payload.to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };
        let _ = self.event_tx.send(P2pEvent::BroadcastMessage(msg)).await;
        Ok(())
    }

    /// 获取配置
    pub fn config(&self) -> &P2pConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2p_config_default() {
        let config = P2pConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:0");
        assert_eq!(config.node_name, "yma-node");
        assert_eq!(config.heartbeat_interval_secs, 15);
        assert_eq!(config.max_peers, 50);
    }

    #[test]
    fn test_p2p_node_creation() {
        let config = P2pConfig::default();
        let node = P2pNode::new(config);
        assert!(!node.node_id().is_empty());
    }

    #[tokio::test]
    async fn test_add_and_remove_peer() {
        let config = P2pConfig::default();
        let node = P2pNode::new(config);

        assert_eq!(node.peer_count().await, 0);
        node.add_peer("peer-1".to_string()).await;
        assert_eq!(node.peer_count().await, 1);

        let peers = node.connected_peers().await;
        assert!(peers.contains(&"peer-1".to_string()));

        node.remove_peer("peer-1").await;
        assert_eq!(node.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_send_message() {
        let config = P2pConfig::default();
        let node = P2pNode::new(config);

        let result = node.send_message("peer-1", "chat", r#"{"text":"hello"}"#).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast() {
        let config = P2pConfig::default();
        let node = P2pNode::new(config);

        let result = node.broadcast("announce", r#"{"event":"node_online"}"#).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_p2p_message_serialization() {
        let msg = P2pMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            sender_id: "sender-1".to_string(),
            receiver_id: None,
            msg_type: "test".to_string(),
            payload: r#"{"key":"value"}"#.to_string(),
            timestamp_ms: 1700000000000,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: P2pMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.msg_type, "test");
        assert_eq!(parsed.sender_id, "sender-1");
    }
}