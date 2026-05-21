use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_LOCKOUT_DURATION_SECONDS: u64 = 300;
const DEFAULT_WINDOW_SECONDS: u64 = 60;

#[derive(Clone)]
pub struct AttemptRecord {
    pub count: u32,
    pub first_attempt_at: u64,
    pub last_attempt_at: u64,
    pub locked_until: Option<u64>,
}

pub struct BruteForceGuard {
    records: parking_lot::RwLock<HashMap<String, AttemptRecord>>,
    max_attempts: u32,
    lockout_duration: u64,
    window_seconds: u64,
}

impl BruteForceGuard {
    pub fn new(max_attempts: Option<u32>, lockout_duration: Option<u64>, window_seconds: Option<u64>) -> Self {
        Self {
            records: parking_lot::RwLock::new(HashMap::new()),
            max_attempts: max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS),
            lockout_duration: lockout_duration.unwrap_or(DEFAULT_LOCKOUT_DURATION_SECONDS),
            window_seconds: window_seconds.unwrap_or(DEFAULT_WINDOW_SECONDS),
        }
    }

    pub fn check(&self, identifier: &str) -> CheckResult {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let records = self.records.read();
        if let Some(record) = records.get(identifier) {
            if let Some(locked_until) = record.locked_until {
                if now < locked_until {
                    return CheckResult::Blocked { remaining_seconds: locked_until - now };
                }
            }
            if now - record.first_attempt_at <= self.window_seconds && record.count >= self.max_attempts {
                let locked_until = now + self.lockout_duration;
                drop(records);
                let mut records = self.records.write();
                if let Some(record) = records.get_mut(identifier) {
                    record.locked_until = Some(locked_until);
                }
                return CheckResult::Blocked { remaining_seconds: self.lockout_duration };
            }
            if now - record.first_attempt_at > self.window_seconds && record.count > 0 {
                drop(records);
                let mut records = self.records.write();
                if let Some(record) = records.get_mut(identifier) {
                    record.count = 0;
                    record.first_attempt_at = now;
                }
            }
        }
        CheckResult::Allowed { remaining_attempts: self.remaining_attempts(identifier) }
    }

    pub fn record_failure(&self, identifier: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut records = self.records.write();
        let record = records.entry(identifier.to_string()).or_insert(AttemptRecord {
            count: 0,
            first_attempt_at: now,
            last_attempt_at: now,
            locked_until: None,
        });
        if now - record.first_attempt_at > self.window_seconds {
            record.count = 1;
            record.first_attempt_at = now;
        } else {
            record.count += 1;
        }
        record.last_attempt_at = now;
    }

    pub fn record_success(&self, identifier: &str) {
        let mut records = self.records.write();
        records.remove(identifier);
    }

    pub fn reset(&self, identifier: &str) {
        let mut records = self.records.write();
        records.remove(identifier);
    }

    pub fn is_locked(&self, identifier: &str) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let records = self.records.read();
        records.get(identifier)
            .and_then(|r| r.locked_until)
            .map(|lu| now < lu)
            .unwrap_or(false)
    }

    pub fn failure_count(&self, identifier: &str) -> u32 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let records = self.records.read();
        records.get(identifier)
            .filter(|r| now - r.first_attempt_at <= self.window_seconds)
            .map(|r| r.count)
            .unwrap_or(0)
    }

    fn remaining_attempts(&self, identifier: &str) -> u32 {
        let count = self.failure_count(identifier);
        if count >= self.max_attempts { 0 } else { self.max_attempts - count }
    }

    pub fn clear_all(&self) {
        self.records.write().clear();
    }
}

impl Default for BruteForceGuard {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

pub enum CheckResult {
    Allowed { remaining_attempts: u32 },
    Blocked { remaining_seconds: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_allowed() {
        let guard = BruteForceGuard::default();
        match guard.check("test_user") {
            CheckResult::Allowed { remaining_attempts } => {
                assert_eq!(remaining_attempts, 5);
            }
            CheckResult::Blocked { .. } => panic!("should be allowed"),
        }
    }

    #[test]
    fn test_block_after_max_attempts() {
        let guard = BruteForceGuard::new(Some(3), Some(60), Some(60));
        for _ in 0..3 {
            guard.record_failure("attacker");
        }
        match guard.check("attacker") {
            CheckResult::Blocked { remaining_seconds } => {
                assert!(remaining_seconds <= 60);
            }
            CheckResult::Allowed { .. } => panic!("should be blocked"),
        }
    }

    #[test]
    fn test_reset_after_success() {
        let guard = BruteForceGuard::new(Some(3), Some(60), Some(60));
        for _ in 0..3 {
            guard.record_failure("user");
        }
        guard.record_success("user");
        match guard.check("user") {
            CheckResult::Allowed { .. } => {}
            CheckResult::Blocked { .. } => panic!("should be allowed after reset"),
        }
    }

    #[test]
    fn test_failure_count() {
        let guard = BruteForceGuard::default();
        assert_eq!(guard.failure_count("user"), 0);
        guard.record_failure("user");
        assert_eq!(guard.failure_count("user"), 1);
        guard.record_failure("user");
        assert_eq!(guard.failure_count("user"), 2);
    }

    #[test]
    fn test_is_locked() {
        let guard = BruteForceGuard::new(Some(2), Some(60), Some(60));
        guard.record_failure("user");
        assert!(!guard.is_locked("user"));
        guard.record_failure("user");
        assert!(guard.is_locked("user"));
    }

    #[test]
    fn test_reset() {
        let guard = BruteForceGuard::default();
        guard.record_failure("user");
        assert_eq!(guard.failure_count("user"), 1);
        guard.reset("user");
        assert_eq!(guard.failure_count("user"), 0);
    }

    #[test]
    fn test_clear_all() {
        let guard = BruteForceGuard::default();
        guard.record_failure("user1");
        guard.record_failure("user2");
        guard.clear_all();
        assert_eq!(guard.failure_count("user1"), 0);
        assert_eq!(guard.failure_count("user2"), 0);
    }

    #[test]
    fn test_different_identifiers_independent() {
        let guard = BruteForceGuard::new(Some(2), Some(60), Some(60));
        guard.record_failure("attacker");
        assert!(guard.check("innocent").remaining_attempts() > 0);
    }

    #[test]
    fn test_window_expiry() {
        let guard = BruteForceGuard::new(Some(2), Some(60), Some(1));
        guard.record_failure("user");
        guard.record_failure("user");
        assert!(guard.is_locked("user"));
        std::thread::sleep(std::time::Duration::from_millis(1100));
        guard.record_failure("user");
        assert_eq!(guard.failure_count("user"), 1);
    }
}

impl CheckResult {
    pub fn remaining_attempts(&self) -> u32 {
        match self {
            CheckResult::Allowed { remaining_attempts } => *remaining_attempts,
            CheckResult::Blocked { .. } => 0,
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, CheckResult::Allowed { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, CheckResult::Blocked { .. })
    }
}