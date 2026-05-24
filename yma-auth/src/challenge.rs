use ring::digest;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const CHALLENGE_TTL_SECONDS: u64 = 120;
const MAX_CHALLENGES_PER_USER: usize = 5;

#[derive(Clone)]
pub enum ChallengeType {
    Hashcash { prefix_zeros: u8 },
    Hmac { key: Vec<u8>, message: String },
    Timed { expires_at: u64 },
}

#[derive(Clone)]
pub struct Challenge {
    pub id: String,
    pub user_id: String,
    pub challenge_type: ChallengeType,
    pub expected_response: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub used: bool,
}

pub struct ChallengeManager {
    challenges: parking_lot::RwLock<HashMap<String, Challenge>>,
    user_challenges: parking_lot::RwLock<HashMap<String, Vec<String>>>,
}

impl ChallengeManager {
    pub fn new() -> Self {
        Self {
            challenges: parking_lot::RwLock::new(HashMap::new()),
            user_challenges: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn generate_hashcash(&self, user_id: &str, prefix_zeros: u8) -> Result<Challenge, String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let id = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let message = format!("{}:{}:{}", user_id, nonce, prefix_zeros);
        let hash = digest::digest(&digest::SHA256, message.as_bytes());
        let expected = hex::encode(hash.as_ref());

        let challenge = Challenge {
            id: id.clone(),
            user_id: user_id.to_string(),
            challenge_type: ChallengeType::Hashcash { prefix_zeros },
            expected_response: format!("{}:{}", nonce, expected),
            created_at: now,
            expires_at: now + CHALLENGE_TTL_SECONDS,
            used: false,
        };

        self.store_challenge(user_id, id, challenge)
    }

    pub fn generate_hmac(&self, user_id: &str, message: &str) -> Result<Challenge, String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let id = uuid::Uuid::new_v4().to_string();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, user_id.as_bytes());
        let tag = ring::hmac::sign(&key, message.as_bytes());
        let expected = hex::encode(tag.as_ref());
        let key_bytes = user_id.as_bytes().to_vec();

        let challenge = Challenge {
            id: id.clone(),
            user_id: user_id.to_string(),
            challenge_type: ChallengeType::Hmac {
                key: key_bytes,
                message: message.to_string(),
            },
            expected_response: expected,
            created_at: now,
            expires_at: now + CHALLENGE_TTL_SECONDS,
            used: false,
        };

        self.store_challenge(user_id, id, challenge)
    }

    pub fn generate_timed(&self, user_id: &str, ttl_seconds: u64) -> Result<Challenge, String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let id = uuid::Uuid::new_v4().to_string();
        let expires_at = now + ttl_seconds;
        let expected = format!("{}:{}", user_id, expires_at);

        let challenge = Challenge {
            id: id.clone(),
            user_id: user_id.to_string(),
            challenge_type: ChallengeType::Timed { expires_at },
            expected_response: expected,
            created_at: now,
            expires_at,
            used: false,
        };

        self.store_challenge(user_id, id, challenge)
    }

    pub fn verify(&self, challenge_id: &str, response: &str) -> Result<bool, String> {
        let mut challenges = self.challenges.write();
        let challenge = challenges.get_mut(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;

        if challenge.used {
            return Err("challenge already used".to_string());
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now >= challenge.expires_at {
            return Err("challenge expired".to_string());
        }

        let is_valid = response == challenge.expected_response;
        if is_valid {
            challenge.used = true;
        }

        Ok(is_valid)
    }

    pub fn cleanup_expired(&self) -> usize {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut challenges = self.challenges.write();
        let mut user_challenges = self.user_challenges.write();
        let expired_ids: Vec<String> = challenges.iter()
            .filter(|(_, c)| now >= c.expires_at || c.used)
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(c) = challenges.remove(id) {
                if let Some(list) = user_challenges.get_mut(&c.user_id) {
                    list.retain(|s| s != id);
                }
            }
        }
        count
    }

    fn store_challenge(&self, user_id: &str, id: String, challenge: Challenge) -> Result<Challenge, String> {
        let mut user_challenges = self.user_challenges.write();
        let user_list = user_challenges.entry(user_id.to_string()).or_default();
        if user_list.len() >= MAX_CHALLENGES_PER_USER {
            return Err("max challenges per user exceeded".to_string());
        }
        user_list.push(id.clone());
        self.challenges.write().insert(id.clone(), challenge.clone());
        Ok(challenge)
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hashcash() {
        let mgr = ChallengeManager::new();
        let challenge = mgr.generate_hashcash("user_1", 2).unwrap();
        assert_eq!(challenge.user_id, "user_1");
        assert!(!challenge.expected_response.is_empty());
    }

    #[test]
    fn test_generate_hmac() {
        let mgr = ChallengeManager::new();
        let challenge = mgr.generate_hmac("user_2", "test_message").unwrap();
        assert!(!challenge.expected_response.is_empty());
    }

    #[test]
    fn test_verify_hashcash() {
        let mgr = ChallengeManager::new();
        let challenge = mgr.generate_hashcash("user_3", 1).unwrap();
        let result = mgr.verify(&challenge.id, &challenge.expected_response);
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_wrong_response() {
        let mgr = ChallengeManager::new();
        let challenge = mgr.generate_hashcash("user_4", 1).unwrap();
        let result = mgr.verify(&challenge.id, "wrong_response");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_expired() {
        let mgr = ChallengeManager::new();
        let challenge = mgr.generate_timed("user_5", 0).unwrap();
        let result = mgr.verify(&challenge.id, &challenge.expected_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_reuse_detection() {
        let mgr = ChallengeManager::new();
        let challenge = mgr.generate_hashcash("user_6", 1).unwrap();
        mgr.verify(&challenge.id, &challenge.expected_response).unwrap();
        let result = mgr.verify(&challenge.id, &challenge.expected_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let mgr = ChallengeManager::new();
        mgr.generate_timed("user_7", 0).unwrap();
        mgr.generate_hashcash("user_7", 1).unwrap();
        let cleaned = mgr.cleanup_expired();
        assert_eq!(cleaned, 1);
    }

    #[test]
    fn test_max_challenges() {
        let mgr = ChallengeManager::new();
        for _i in 0..5 {
            mgr.generate_hashcash("user_8", 1).unwrap();
        }
        let result = mgr.generate_hashcash("user_8", 1);
        assert!(result.is_err());
    }
}