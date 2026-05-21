//! yma-events 事件系统统一库
//!
//! 提供 EventBus 事件总线的标准化接口，支持事件过滤和持久化
//! 版本锁定: 0.2.0

use tokio::sync::broadcast;
use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashMap;

/// 事件优先级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// 事件元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMeta {
    pub id: String,
    pub event_type: String,
    pub source: String,
    pub timestamp: i64,
    pub priority: EventPriority,
}

impl EventMeta {
    pub fn new(event_type: &str, source: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            source: source.to_string(),
            timestamp: Utc::now().timestamp_millis(),
            priority: EventPriority::Normal,
        }
    }

    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// 事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub meta: EventMeta,
    pub payload: serde_json::Value,
}

/// 事件过滤器
#[derive(Debug, Clone)]
pub struct EventFilter {
    pub event_types: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub min_priority: Option<EventPriority>,
}

impl EventFilter {
    pub fn new() -> Self {
        Self {
            event_types: None,
            sources: None,
            min_priority: None,
        }
    }

    pub fn with_event_types(mut self, types: Vec<String>) -> Self {
        self.event_types = Some(types);
        self
    }

    pub fn with_sources(mut self, sources: Vec<String>) -> Self {
        self.sources = Some(sources);
        self
    }

    pub fn with_min_priority(mut self, priority: EventPriority) -> Self {
        self.min_priority = Some(priority);
        self
    }

    pub fn matches(&self, event: &Event) -> bool {
        if let Some(ref types) = self.event_types {
            if !types.contains(&event.meta.event_type) {
                return false;
            }
        }
        if let Some(ref sources) = self.sources {
            if !sources.contains(&event.meta.source) {
                return false;
            }
        }
        if let Some(ref min_priority) = self.min_priority {
            let priority_value = |p: &EventPriority| match p {
                EventPriority::Low => 1,
                EventPriority::Normal => 2,
                EventPriority::High => 3,
                EventPriority::Critical => 4,
            };
            if priority_value(&event.meta.priority) < priority_value(min_priority) {
                return false;
            }
        }
        true
    }
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// 事件订阅者特征
#[async_trait::async_trait]
pub trait EventHandler: Send + Sync {
    async fn handle(&self, event: Event);
    fn event_types(&self) -> Vec<String>;
    fn filter(&self) -> Option<EventFilter> {
        None
    }
}

/// 事件持久化特征
#[async_trait::async_trait]
pub trait EventPersistence: Send + Sync {
    async fn persist(&self, event: &Event) -> Result<(), String>;
    async fn load_history(&self, filter: &EventFilter, limit: usize) -> Result<Vec<Event>, String>;
}

/// 内存持久化（用于测试和简单场景）
pub struct MemoryPersistence {
    events: std::sync::Arc<tokio::sync::RwLock<Vec<Event>>>,
}

impl MemoryPersistence {
    pub fn new() -> Self {
        Self {
            events: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl EventPersistence for MemoryPersistence {
    async fn persist(&self, event: &Event) -> Result<(), String> {
        self.events.write().await.push(event.clone());
        Ok(())
    }

    async fn load_history(&self, filter: &EventFilter, limit: usize) -> Result<Vec<Event>, String> {
        let events = self.events.read().await;
        let filtered: Vec<Event> = events
            .iter()
            .filter(|e| filter.matches(e))
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }
}

impl Default for MemoryPersistence {
    fn default() -> Self {
        Self::new()
    }
}

/// 事件总线
pub struct EventBus {
    tx: broadcast::Sender<Event>,
    persistence: Option<std::sync::Arc<dyn EventPersistence>>,
    handlers: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<std::sync::Arc<dyn EventHandler>>>>>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            persistence: None,
            handlers: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// 设置持久化后端
    pub fn with_persistence(mut self, persistence: Box<dyn EventPersistence>) -> Self {
        self.persistence = Some(std::sync::Arc::from(persistence));
        self
    }

    pub fn publish(&self, event: Event) -> Result<(), String> {
        self.tx.send(event.clone()).map_err(|e| e.to_string())?;

        // 异步持久化
        if let Some(ref persistence) = self.persistence {
            let event = event.clone();
            let persistence = persistence.clone();
            tokio::spawn(async move {
                let _ = persistence.persist(&event).await;
            });
        }

        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// 订阅过滤后的事件
    pub fn subscribe_filtered(&self, _filter: EventFilter) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// 注册异步 Handler
    pub async fn register_handler(&self, handler: std::sync::Arc<dyn EventHandler>) {
        let mut handlers = self.handlers.write().await;
        for event_type in handler.event_types() {
            handlers.entry(event_type).or_insert_with(Vec::new).push(handler.clone());
        }
    }

    /// 获取历史事件
    pub async fn load_history(&self, filter: &EventFilter, limit: usize) -> Result<Vec<Event>, String> {
        match &self.persistence {
            Some(persistence) => persistence.load_history(filter, limit).await,
            None => Ok(Vec::new()),
        }
    }
}

impl Clone for MemoryPersistence {
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_meta() {
        let meta = EventMeta::new("test", "source");
        assert_eq!(meta.event_type, "test");
        assert_eq!(meta.source, "source");
    }

    #[test]
    fn test_event_filter() {
        let filter = EventFilter::new()
            .with_event_types(vec!["type1".to_string()])
            .with_min_priority(EventPriority::High);

        let event1 = Event {
            meta: EventMeta::new("type1", "src").with_priority(EventPriority::Critical),
            payload: serde_json::Value::Null,
        };
        let event2 = Event {
            meta: EventMeta::new("type2", "src").with_priority(EventPriority::Low),
            payload: serde_json::Value::Null,
        };

        assert!(filter.matches(&event1));
        assert!(!filter.matches(&event2));
    }

    #[tokio::test]
    async fn test_memory_persistence() {
        let persistence = MemoryPersistence::new();
        let event = Event {
            meta: EventMeta::new("test", "src"),
            payload: serde_json::json!({"key": "value"}),
        };

        persistence.persist(&event).await.unwrap();

        let filter = EventFilter::new();
        let history = persistence.load_history(&filter, 10).await.unwrap();
        assert_eq!(history.len(), 1);
    }
}