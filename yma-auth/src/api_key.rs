use uuid::Uuid;

/// API Key 生成器
pub struct ApiKeyGenerator;

impl ApiKeyGenerator {
    /// 生成 API Key
    pub fn generate() -> (String, String) {
        let key_id = Uuid::new_v4().to_string();
        let secret = Uuid::new_v4().to_string().replace('-', "");
        let api_key = format!("yma_{}_{}", &key_id[..8], &secret[..24]);
        (key_id, api_key)
    }

    /// 验证 API Key 格式
    pub fn validate(api_key: &str) -> bool {
        if !api_key.starts_with("yma_") {
            return false;
        }
        let parts: Vec<&str> = api_key.split('_').collect();
        parts.len() == 3 && parts[1].len() == 8 && parts[2].len() == 24
    }

    /// 从 API Key 提取 Key ID
    pub fn extract_key_id(api_key: &str) -> Option<String> {
        if Self::validate(api_key) {
            api_key.split('_').nth(1).map(|s| s.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_generate() {
        let (key_id, api_key) = ApiKeyGenerator::generate();
        assert!(!key_id.is_empty());
        assert!(api_key.starts_with("yma_"));
        assert_eq!(api_key.len(), 35);
    }

    #[test]
    fn test_api_key_validate() {
        let (_, api_key) = ApiKeyGenerator::generate();
        assert!(ApiKeyGenerator::validate(&api_key));
        assert!(!ApiKeyGenerator::validate("invalid_key"));
        assert!(!ApiKeyGenerator::validate(""));
    }

    #[test]
    fn test_api_key_extract_id() {
        let (key_id, api_key) = ApiKeyGenerator::generate();
        let extracted = ApiKeyGenerator::extract_key_id(&api_key).unwrap();
        assert_eq!(&key_id[..8], &extracted);
    }

    #[test]
    fn test_api_key_different_each_time() {
        let (_, key1) = ApiKeyGenerator::generate();
        let (_, key2) = ApiKeyGenerator::generate();
        assert_ne!(key1, key2);
    }
}