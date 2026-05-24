use crate::totp::TotpService;
use ring::rand::SecureRandom;
use std::collections::HashMap;

pub enum MfaMethod {
    Totp,
    Sms,
    Email,
}

pub struct MfaConfig {
    pub enabled: bool,
    pub methods: Vec<MfaMethod>,
    pub totp_secret: Vec<u8>,
    pub backup_codes: Vec<String>,
}

pub struct MfaService {
    configs: parking_lot::RwLock<HashMap<String, MfaConfig>>,
}

impl MfaService {
    pub fn new() -> Self {
        Self {
            configs: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn enable_totp(&self, user_id: &str) -> Result<Vec<u8>, String> {
        let secret = TotpService::generate_secret();
        let mut configs = self.configs.write();
        let backup_codes = Self::generate_backup_codes();
        configs.insert(user_id.to_string(), MfaConfig {
            enabled: true,
            methods: vec![MfaMethod::Totp],
            totp_secret: secret.clone(),
            backup_codes,
        });
        Ok(secret)
    }

    pub fn verify_totp(&self, user_id: &str, code: &str) -> Result<bool, String> {
        let configs = self.configs.read();
        let config = configs.get(user_id).ok_or_else(|| "mfa not enabled".to_string())?;
        if !config.enabled {
            return Ok(false);
        }
        TotpService::verify(&config.totp_secret, code, 1)
    }

    pub fn is_enabled(&self, user_id: &str) -> bool {
        self.configs.read().get(user_id).map(|c| c.enabled).unwrap_or(false)
    }

    pub fn disable(&self, user_id: &str) {
        self.configs.write().remove(user_id);
    }

    pub fn verify_backup_code(&self, user_id: &str, code: &str) -> bool {
        let mut configs = self.configs.write();
        if let Some(config) = configs.get_mut(user_id) {
            if let Some(pos) = config.backup_codes.iter().position(|c| c == code) {
                config.backup_codes.remove(pos);
                return true;
            }
        }
        false
    }

    fn generate_backup_codes() -> Vec<String> {
        let rng = ring::rand::SystemRandom::new();
        (0..8).map(|_| {
            let mut bytes = [0u8; 4];
            rng.fill(&mut bytes).ok();
            hex::encode(bytes).to_uppercase()
        }).collect()
    }
}

impl Default for MfaService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_enable_totp() {
        let mfa = MfaService::new();
        let secret = mfa.enable_totp("user_1").unwrap();
        assert_eq!(secret.len(), 20);
        assert!(mfa.is_enabled("user_1"));
    }

    #[test]
    fn test_mfa_verify_totp() {
        let mfa = MfaService::new();
        mfa.enable_totp("user_2").unwrap();
        let code = TotpService::generate(&mfa.configs.read().get("user_2").unwrap().totp_secret, None).unwrap();
        assert!(mfa.verify_totp("user_2", &code).unwrap());
    }

    #[test]
    fn test_mfa_disabled_by_default() {
        let mfa = MfaService::new();
        assert!(!mfa.is_enabled("unknown"));
    }

    #[test]
    fn test_mfa_disable() {
        let mfa = MfaService::new();
        mfa.enable_totp("user_3").unwrap();
        assert!(mfa.is_enabled("user_3"));
        mfa.disable("user_3");
        assert!(!mfa.is_enabled("user_3"));
    }

    #[test]
    fn test_mfa_verify_wrong_code() {
        let mfa = MfaService::new();
        mfa.enable_totp("user_4").unwrap();
        assert!(!mfa.verify_totp("user_4", "000000").unwrap());
    }

    #[test]
    fn test_mfa_backup_code() {
        let mfa = MfaService::new();
        mfa.enable_totp("user_5").unwrap();
        let code = {
            let binding = mfa.configs.read();
            binding.get("user_5").unwrap().backup_codes[0].clone()
        };
        assert!(mfa.verify_backup_code("user_5", &code));
        assert!(!mfa.verify_backup_code("user_5", &code));
    }
}