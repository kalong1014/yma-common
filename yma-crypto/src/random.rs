//! yma-crypto::random — 安全随机数生成

use ring::rand::SecureRandom as _;

/// 安全随机数生成器
pub struct RandomGenerator;

impl RandomGenerator {
    pub fn new() -> Self {
        Self
    }

    /// 生成指定长度的随机字节
    pub fn generate_bytes(&self, len: usize) -> Result<Vec<u8>, String> {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes)
            .map_err(|_| "Failed to generate random bytes".to_string())?;
        Ok(bytes)
    }

    /// 生成随机 u64
    pub fn generate_u64(&self) -> Result<u64, String> {
        let bytes = self.generate_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(arr))
    }

    /// 生成随机 32 字节 (256位，适合作为密钥)
    pub fn generate_key_256(&self) -> Result<[u8; 32], String> {
        let bytes = self.generate_bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// 生成随机 16 字节 (128位)
    pub fn generate_key_128(&self) -> Result<[u8; 16], String> {
        let bytes = self.generate_bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// 生成指定长度的随机字节（便捷方法）
    pub fn bytes(&self, len: usize) -> Vec<u8> {
        self.generate_bytes(len).expect("Failed to generate random bytes")
    }

    /// 生成 UUID v4 字符串
    pub fn uuid_v4(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

impl Default for RandomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// 向后兼容别名
pub type SecureRandom = RandomGenerator;

/// 便捷函数：生成随机字节
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    RandomGenerator::new().generate_bytes(len).expect("Random generation failed")
}

/// 字符集枚举
#[derive(Debug, Clone, Copy)]
pub enum Charset {
    /// 字母+数字
    Alphanumeric,
    /// 纯数字
    Numeric,
    /// 可打印ASCII（0x20-0x7E）
    Ascii,
    /// 纯字母
    Alpha,
}

/// 生成指定长度的随机字符串
pub fn generate_random_string(length: usize, charset: Charset) -> String {
    use rand::Rng;
    let chars: Vec<char> = match charset {
        Charset::Alphanumeric => {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                .chars().collect()
        }
        Charset::Numeric => "0123456789".chars().collect(),
        Charset::Ascii => (0x20u8..0x7F)
            .filter_map(|c| char::from_u32(c as u32))
            .collect(),
        Charset::Alpha => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            .chars().collect(),
    };
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bytes() {
        let rng = SecureRandom::new();
        let b1 = rng.generate_bytes(32).unwrap();
        let b2 = rng.generate_bytes(32).unwrap();
        assert_eq!(b1.len(), 32);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_generate_u64() {
        let rng = SecureRandom::new();
        let n1 = rng.generate_u64().unwrap();
        let n2 = rng.generate_u64().unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_generate_key_256() {
        let rng = SecureRandom::new();
        let k1 = rng.generate_key_256().unwrap();
        let k2 = rng.generate_key_256().unwrap();
        assert_eq!(k1.len(), 32);
        assert_ne!(k1, k2);
    }
}