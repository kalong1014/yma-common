use ring::hmac;
use ring::rand::SecureRandom;
use std::time::{SystemTime, UNIX_EPOCH};

const TOTP_INTERVAL: u64 = 30;
const TOTP_DIGITS: u32 = 6;

/// TOTP 服务
pub struct TotpService;

impl TotpService {
    /// 生成 TOTP 验证码
    pub fn generate(secret: &[u8], timestamp: Option<u64>) -> Result<String, String> {
        let time = timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        let counter = time / TOTP_INTERVAL;
        let counter_bytes = counter.to_be_bytes();

        let signing_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
        let tag = hmac::sign(&signing_key, &counter_bytes);

        let offset = (tag.as_ref().last().unwrap_or(&0) & 0x0f) as usize;
        let code = ((u32::from(tag.as_ref()[offset]) & 0x7f) << 24)
            | (u32::from(tag.as_ref()[offset + 1]) << 16)
            | (u32::from(tag.as_ref()[offset + 2]) << 8)
            | u32::from(tag.as_ref()[offset + 3]);

        let code = code % 10u32.pow(TOTP_DIGITS);
        Ok(format!("{:0width$}", code, width = TOTP_DIGITS as usize))
    }

    /// 验证 TOTP 验证码
    pub fn verify(secret: &[u8], code: &str, window: u8) -> Result<bool, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let window_size = window as i64;
        for offset in -window_size..=window_size {
            let timestamp = if offset >= 0 {
                now + (offset as u64)
            } else {
                now.saturating_sub((-offset) as u64)
            };
            let expected = Self::generate(secret, Some(timestamp))?;
            if expected == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 生成 TOTP 密钥
    pub fn generate_secret() -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();
        let mut secret = vec![0u8; 20];
        rng.fill(&mut secret).unwrap();
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generate() {
        let secret = TotpService::generate_secret();
        let code = TotpService::generate(&secret, None).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_verify() {
        let secret = TotpService::generate_secret();
        let code = TotpService::generate(&secret, None).unwrap();
        assert!(TotpService::verify(&secret, &code, 1).unwrap());
    }

    #[test]
    fn test_totp_wrong_code() {
        let secret = TotpService::generate_secret();
        assert!(!TotpService::verify(&secret, "000000", 1).unwrap());
    }

    #[test]
    fn test_totp_known_timestamp() {
        let secret = b"test_secret_key_12345";
        let code = TotpService::generate(secret, Some(1700000000)).unwrap();
        assert_eq!(code.len(), 6);
    }
}