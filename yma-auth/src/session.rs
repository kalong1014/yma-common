use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_SESSION_TTL_SECONDS: u64 = 3600;
const MAX_SESSIONS_PER_USER: usize = 50;

#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub data: HashMap<String, String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_access_at: u64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl Session {
    pub fn new(user_id: &str, ttl_seconds: Option<u64>) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let ttl = ttl_seconds.unwrap_or(DEFAULT_SESSION_TTL_SECONDS);
        let id = uuid::Uuid::new_v4().to_string();
        Self {
            id,
            user_id: user_id.to_string(),
            data: HashMap::new(),
            created_at: now,
            expires_at: now + ttl,
            last_access_at: now,
            ip_address: None,
            user_agent: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now >= self.expires_at
    }

    pub fn touch(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.last_access_at = now;
    }

    pub fn extend_ttl(&mut self, ttl_seconds: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.expires_at = now + ttl_seconds;
    }

    pub fn set_data(&mut self, key: &str, value: &str) {
        self.data.insert(key.to_string(), value.to_string());
    }

    pub fn get_data(&self, key: &str) -> Option<&String> {
        self.data.get(key)
    }
}

pub struct SessionStore {
    sessions: parking_lot::RwLock<HashMap<String, Session>>,
    user_sessions: parking_lot::RwLock<HashMap<String, Vec<String>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: parking_lot::RwLock::new(HashMap::new()),
            user_sessions: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn create_session(&self, user_id: &str, ttl_seconds: Option<u64>) -> Result<Session, String> {
        let mut user_sessions = self.user_sessions.write();
        let user_list = user_sessions.entry(user_id.to_string()).or_default();
        if user_list.len() >= MAX_SESSIONS_PER_USER {
            return Err("max sessions per user exceeded".to_string());
        }
        let session = Session::new(user_id, ttl_seconds);
        let session_id = session.id.clone();
        user_list.push(session_id.clone());
        self.sessions.write().insert(session_id.clone(), session.clone());
        Ok(session)
    }

    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read();
        sessions.get(session_id).cloned()
    }

    pub fn get_valid_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read();
        sessions.get(session_id).and_then(|s| {
            if s.is_expired() { None } else { Some(s.clone()) }
        })
    }

    pub fn update_session<F>(&self, session_id: &str, f: F) -> bool
    where
        F: FnOnce(&mut Session),
    {
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.get_mut(session_id) {
            f(session);
            true
        } else {
            false
        }
    }

    pub fn remove_session(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write();
        let removed = sessions.remove(session_id);
        if let Some(session) = &removed {
            let mut user_sessions = self.user_sessions.write();
            if let Some(list) = user_sessions.get_mut(&session.user_id) {
                list.retain(|s| s != session_id);
            }
        }
        removed.is_some()
    }

    pub fn remove_user_sessions(&self, user_id: &str) -> usize {
        let mut user_sessions = self.user_sessions.write();
        let mut sessions = self.sessions.write();
        let mut count = 0;
        if let Some(session_ids) = user_sessions.remove(user_id) {
            for sid in &session_ids {
                sessions.remove(sid);
                count += 1;
            }
        }
        count
    }

    pub fn user_session_count(&self, user_id: &str) -> usize {
        self.user_sessions.read().get(user_id).map(|l| l.len()).unwrap_or(0)
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write();
        let mut user_sessions = self.user_sessions.write();
        let expired_ids: Vec<String> = sessions.iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(session) = sessions.remove(id) {
                if let Some(list) = user_sessions.get_mut(&session.user_id) {
                    list.retain(|s| s != id);
                }
            }
        }
        count
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_new() {
        let session = Session::new("user_1", None);
        assert_eq!(session.user_id, "user_1");
        assert!(!session.id.is_empty());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expired() {
        let session = Session::new("user_2", Some(0));
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_store_create() {
        let store = SessionStore::new();
        let session = store.create_session("user_1", None).unwrap();
        assert_eq!(session.user_id, "user_1");
        assert_eq!(store.session_count(), 1);
    }

    #[test]
    fn test_session_store_get() {
        let store = SessionStore::new();
        let session = store.create_session("user_1", None).unwrap();
        let found = store.get_session(&session.id).unwrap();
        assert_eq!(found.id, session.id);
    }

    #[test]
    fn test_session_store_remove() {
        let store = SessionStore::new();
        let session = store.create_session("user_1", None).unwrap();
        assert!(store.remove_session(&session.id));
        assert_eq!(store.session_count(), 0);
    }

    #[test]
    fn test_session_store_remove_user() {
        let store = SessionStore::new();
        store.create_session("user_1", None).unwrap();
        store.create_session("user_1", None).unwrap();
        assert_eq!(store.remove_user_sessions("user_1"), 2);
        assert_eq!(store.session_count(), 0);
    }

    #[test]
    fn test_session_store_cleanup_expired() {
        let store = SessionStore::new();
        store.create_session("user_1", Some(3600)).unwrap();
        store.create_session("user_2", Some(0)).unwrap();
        assert_eq!(store.cleanup_expired(), 1);
        assert_eq!(store.session_count(), 1);
    }

    #[test]
    fn test_session_max_per_user() {
        let store = SessionStore::new();
        for i in 0..50 {
            store.create_session(&format!("user_{}", i % 2), None).unwrap();
        }
        let result = store.create_session("user_0", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_touch_and_extend() {
        let store = SessionStore::new();
        let session = store.create_session("user_1", Some(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.update_session(&session.id, |s| {
            s.extend_ttl(3600);
        });
        let updated = store.get_session(&session.id).unwrap();
        assert!(!updated.is_expired());
    }

    #[test]
    fn test_get_valid_session_expired() {
        let store = SessionStore::new();
        let session = store.create_session("user_1", Some(0)).unwrap();
        assert!(store.get_valid_session(&session.id).is_none());
    }
}