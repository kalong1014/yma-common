use ring::pbkdf2;
use std::num::NonZeroU32;

const HASH_COST: u32 = 12;

/// 密码哈希器
pub struct PasswordHasher;

impl PasswordHasher {
    /// 哈希密码（使用默认 cost）
    pub fn hash(password: &str) -> Result<String, String> {
        bcrypt::hash(password, HASH_COST).map_err(|e| format!("Password hash failed: {}", e))
    }

    /// 验证密码
    pub fn verify(password: &str, hashed: &str) -> Result<bool, String> {
        bcrypt::verify(password, hashed).map_err(|e| format!("Password verify failed: {}", e))
    }

    /// 使用 PBKDF2-SHA256 哈希密码
    pub fn hash_pbkdf2(password: &str, salt: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(100_000).unwrap(),
            salt,
            password.as_bytes(),
            &mut out,
        );
        out
    }

    /// 验证 PBKDF2 密码
    pub fn verify_pbkdf2(password: &str, salt: &[u8], expected: &[u8]) -> bool {
        let computed = Self::hash_pbkdf2(password, salt);
        computed.len() == expected.len() && computed.iter().zip(expected.iter()).all(|(a, b)| a == b)
    }
}

/// 哈希密码（支持自定义 cost）
pub fn hash_password(password: &str, cost: u32) -> Result<String, String> {
    bcrypt::hash(password, cost).map_err(|e| format!("Password hash failed: {}", e))
}

/// 验证密码
pub fn verify_password(password: &str, hashed: &str) -> Result<bool, String> {
    bcrypt::verify(password, hashed).map_err(|e| format!("Password verify failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SecureRandom;

    const HASH_SALT_LEN: usize = 16;

    #[test]
    fn test_password_hash_verify() {
        let password = "SecureP@ss123";
        let hash = PasswordHasher::hash(password).unwrap();
        assert!(PasswordHasher::verify(password, &hash).unwrap());
        assert!(!PasswordHasher::verify("WrongPass", &hash).unwrap());
    }

    #[test]
    fn test_password_pbkdf2() {
        let mut salt = vec![0u8; HASH_SALT_LEN];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut salt).unwrap();

        let hash = PasswordHasher::hash_pbkdf2("my_password", &salt);
        assert!(PasswordHasher::verify_pbkdf2("my_password", &salt, &hash));
        assert!(!PasswordHasher::verify_pbkdf2("wrong_password", &salt, &hash));
    }

    #[test]
    fn test_password_hash_min_length() {
        let password = "Abc123!@";
        let hash = PasswordHasher::hash(password).unwrap();
        assert!(PasswordHasher::verify(password, &hash).unwrap());
    }
}