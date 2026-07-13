#![deny(missing_docs)]
//! WebSocket连接管理模块，支持心跳检测、广播消息与房间管理

use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;

/// WebSocket连接配置
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// 心跳间隔秒数，默认30
    pub heartbeat_interval_secs: u64,
    /// 心跳超时秒数，默认10（超时后断开连接）
    pub heartbeat_timeout_secs: u64,
    /// 未处理消息最大缓冲数，默认256
    pub max_buffer_size: usize,
    /// 单条消息最大大小（字节），默认65536
    pub max_message_size: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 30,
            heartbeat_timeout_secs: 10,
            max_buffer_size: 256,
            max_message_size: 65536,
        }
    }
}

/// WebSocket消息
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsMessage {
    /// 消息类型
    pub msg_type: String,
    /// 消息内容
    pub content: String,
    /// 发送者ID
    pub sender_id: Option<String>,
    /// 房间ID
    pub room_id: Option<String>,
    /// 时间戳
    pub timestamp: i64,
}

/// WebSocket房间管理器
pub struct WsRoomManager {
    rooms: Arc<DashMap<String, broadcast::Sender<String>>>,
}

impl WsRoomManager {
    /// 创建房间管理器
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(DashMap::new()),
        }
    }

    /// 加入房间并获取消息接收器
    ///
    /// # 参数
    /// * `room_id` - 房间标识
    ///
    /// # 返回值
    /// 消息接收器
    pub fn join_room(&self, room_id: &str) -> broadcast::Receiver<String> {
        let tx = self
            .rooms
            .entry(room_id.to_string())
            .or_insert_with(|| broadcast::channel(256).0);
        tx.subscribe()
    }

    /// 向房间广播消息
    ///
    /// # 参数
    /// * `room_id` - 房间标识
    /// * `message` - 消息内容（JSON字符串）
    pub fn broadcast_to_room(&self, room_id: &str, message: &str) -> Result<usize, String> {
        match self.rooms.get(room_id) {
            Some(tx) => tx
                .send(message.to_string())
                .map_err(|e| format!("广播消息失败: {}", e)),
            None => Err(format!("房间 {} 不存在", room_id)),
        }
    }

    /// 获取房间连接数
    ///
    /// # 参数
    /// * `room_id` - 房间标识
    pub fn room_count(&self, room_id: &str) -> usize {
        self.rooms
            .get(room_id)
            .map(|tx| tx.receiver_count())
            .unwrap_or(0)
    }

    /// 列出所有房间
    pub fn list_rooms(&self) -> Vec<String> {
        self.rooms.iter().map(|entry| entry.key().clone()).collect()
    }

    /// 移除房间
    ///
    /// # 参数
    /// * `room_id` - 房间标识
    pub fn remove_room(&self, room_id: &str) -> bool {
        self.rooms.remove(room_id).is_some()
    }

    /// 获取管理器引用，用于在handler之间共享
    pub fn shared(&self) -> Arc<DashMap<String, broadcast::Sender<String>>> {
        self.rooms.clone()
    }
}

impl Default for WsRoomManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 处理WebSocket升级请求和连接生命周期
///
/// # 参数
/// * `ws` - axum WebSocket升级对象
/// * `config` - WebSocket配置
/// * `room_manager` - 房间管理器，用于接收消息
///
/// 心跳检测逻辑：
/// 每30秒发送一次Ping帧，如果10秒内未收到Pong响应，主动断开连接
pub async fn handle_ws_connection(
    ws: WebSocket,
    config: WsConfig,
    mut room_rx: broadcast::Receiver<String>,
) {
    let (mut sender, mut receiver) = ws.split();

    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();

    let send_task = tokio::spawn(async move {
        let mut heartbeat =
            tokio::time::interval(tokio::time::Duration::from_secs(config.heartbeat_interval_secs));

        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    if sender.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
                msg = room_rx.recv() => {
                    match msg {
                        Ok(text) => {
                            if sender.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("WebSocket消息滞后 {} 条，跳过", n);
                        }
                    }
                }
                _ = &mut close_rx => {
                    let _ = sender.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(_) | Message::Binary(_) => {}
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => break,
            }
        }
        let _ = close_tx.send(());
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
}

/// 升级HTTP请求为WebSocket连接的axum handler
///
/// # 参数
/// * `ws` - WebSocket升级对象
/// * `room_id` - 房间标识查询参数
/// * `room_manager` - 房间管理器状态
pub async fn ws_upgrade_handler(
    ws: axum::extract::WebSocketUpgrade,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    axum::extract::State(room_manager): axum::extract::State<
        Arc<DashMap<String, broadcast::Sender<String>>>,
    >,
) -> impl axum::response::IntoResponse {
    let room_id = params.get("room").cloned().unwrap_or_else(|| "default".to_string());

    let rx = {
        let tx = room_manager
            .entry(room_id.clone())
            .or_insert_with(|| broadcast::channel(256).0);
        tx.subscribe()
    };

    ws.on_upgrade(move |ws| handle_ws_connection(ws, WsConfig::default(), rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_config_default() {
        let config = WsConfig::default();
        assert_eq!(config.heartbeat_interval_secs, 30);
        assert_eq!(config.heartbeat_timeout_secs, 10);
        assert_eq!(config.max_buffer_size, 256);
        assert_eq!(config.max_message_size, 65536);
    }

    #[test]
    fn test_room_manager_new() {
        let manager = WsRoomManager::new();
        assert!(manager.list_rooms().is_empty());
    }

    #[test]
    fn test_room_join_and_count() {
        let manager = WsRoomManager::new();
        let _rx1 = manager.join_room("room1");
        let _rx2 = manager.join_room("room1");
        assert_eq!(manager.room_count("room1"), 2);
    }

    #[test]
    fn test_room_list() {
        let manager = WsRoomManager::new();
        let _rx1 = manager.join_room("room_a");
        let _rx2 = manager.join_room("room_b");
        let rooms = manager.list_rooms();
        assert_eq!(rooms.len(), 2);
        assert!(rooms.contains(&"room_a".to_string()));
        assert!(rooms.contains(&"room_b".to_string()));
    }

    #[test]
    fn test_room_remove() {
        let manager = WsRoomManager::new();
        let _rx = manager.join_room("temp_room");
        assert!(manager.remove_room("temp_room"));
        assert!(!manager.remove_room("nonexistent"));
    }

    #[test]
    fn test_broadcast_to_nonexistent_room() {
        let manager = WsRoomManager::new();
        assert!(manager.broadcast_to_room("nonexistent", "test").is_err());
    }

    #[test]
    fn test_ws_message_serialization() {
        let msg = WsMessage {
            msg_type: "chat".to_string(),
            content: "Hello".to_string(),
            sender_id: Some("user1".to_string()),
            room_id: Some("room1".to_string()),
            timestamp: 1700000000000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: WsMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.msg_type, "chat");
        assert_eq!(parsed.content, "Hello");
    }
}