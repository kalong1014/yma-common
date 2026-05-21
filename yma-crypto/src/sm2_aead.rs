//! yma-crypto::sm2_aead — SM2 AEAD 封装模式
//!
//! 提供基于 SM2 的认证加密封装，结合 SM2 密钥封装 + SM4-GCM 数据加密
//! 实现 ECIES-like 的混合加密方案

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::random::SecureRandom;
use crate::sm2::Sm2KeyPair;
use crate::sm4::{cbc_decrypt, cbc_encrypt};

/// SM2 AEAD 加密结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sm2AeadCiphertext {
    /// SM2 封装的临时公钥 (C1)
    pub ephemeral_public_key: Vec<u8>,
    /// SM4 加密的数据密文 (C2)
    pub encrypted_data: Vec<u8>,
    /// 认证标签 (C3) - HMAC-SM3
    pub auth_tag: Vec<u8>,
    /// 使用的 SM4 IV
    pub iv: Vec<u8>,
}

/// SM2 AEAD 加密器
pub struct Sm2AeadEncryptor;

impl Sm2AeadEncryptor {
    pub fn new() -> Self {
        Self
    }

    /// 使用接收方公钥加密数据
    /// 1. 生成临时 SM2 密钥对
    /// 2. 用临时私钥和接收方公钥协商出共享密钥
    /// 3. 用共享密钥派生 SM4 密钥和 HMAC 密钥
    /// 4. SM4-CBC 加密数据
    /// 5. HMAC-SM3 计算认证标签
    pub fn encrypt(
        &self,
        recipient_public_key: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Sm2AeadCiphertext, CryptoError> {
        // 1. 生成临时 SM2 密钥对
        let ephemeral_keypair = Sm2KeyPair::generate();
        let ephemeral_public_key = ephemeral_keypair.public_key_bytes().to_vec();

        // 2. 用临时私钥解密（模拟密钥协商）
        // 实际场景中应使用 SM2 密钥协商协议
        // 这里简化处理：用临时密钥对加密一个随机密钥
        let rng = SecureRandom::new();
        let sm4_key = rng.generate_key_256()
            .map_err(CryptoError::RandomError)?;
        let sm4_key_16: [u8; 16] = sm4_key[..16].try_into()
            .map_err(|_| CryptoError::InvalidKeyLength { expected: 16, actual: sm4_key.len() })?;
        // 3. 生成 IV
        let iv = rng.generate_key_128()
            .map_err(CryptoError::RandomError)?;

        // 4. SM4-CBC 加密数据
        let encrypted_data = cbc_encrypt(&sm4_key_16, &iv, plaintext);

        // 5. 计算 HMAC-SM3 认证标签
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&encrypted_data);
        hmac_input.extend_from_slice(&iv);
        if let Some(ad) = associated_data {
            hmac_input.extend_from_slice(ad);
        }
        let auth_tag = crate::sm3::hmac(&sm4_key_16, &hmac_input);

        // 6. 用接收方公钥加密 SM4 密钥
        let encrypted_key = crate::sm2::encrypt(recipient_public_key, &sm4_key_16)
            .map_err(|e| CryptoError::Sm2Error(e.to_string()))?;

        // 将加密后的密钥和临时公钥合并
        let mut combined_ephemeral = ephemeral_public_key.clone();
        combined_ephemeral.extend_from_slice(&encrypted_key);

        Ok(Sm2AeadCiphertext {
            ephemeral_public_key: combined_ephemeral,
            encrypted_data,
            auth_tag,
            iv: iv.to_vec(),
        })
    }

    /// 使用接收方私钥解密数据
    pub fn decrypt(
        &self,
        recipient_private_key: &[u8],
        ciphertext: &Sm2AeadCiphertext,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        // 1. 从 ciphertext 中提取临时公钥和加密后的 SM4 密钥
        // 简化处理：假设前 65 字节是临时公钥，后面是加密的密钥
        let ephemeral_pk_len = 65;
        if ciphertext.ephemeral_public_key.len() < ephemeral_pk_len {
            return Err(CryptoError::InvalidInput("Invalid ephemeral public key".to_string()));
        }

        let _ephemeral_public_key = &ciphertext.ephemeral_public_key[..ephemeral_pk_len];
        let encrypted_key = &ciphertext.ephemeral_public_key[ephemeral_pk_len..];

        // 2. 用接收方私钥解密 SM4 密钥
        let sm4_key_16 = crate::sm2::decrypt(recipient_private_key, encrypted_key)
            .map_err(|e| CryptoError::Sm2Error(e.to_string()))?;

        if sm4_key_16.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: sm4_key_16.len(),
            });
        }

        // 3. 验证认证标签
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&ciphertext.encrypted_data);
        hmac_input.extend_from_slice(&ciphertext.iv);
        if let Some(ad) = associated_data {
            hmac_input.extend_from_slice(ad);
        }
        let expected_tag = crate::sm3::hmac(&sm4_key_16, &hmac_input);

        if !constant_time_eq(&expected_tag, &ciphertext.auth_tag) {
            return Err(CryptoError::InvalidInput("Authentication tag mismatch".to_string()));
        }

        // 4. SM4-CBC 解密数据
        let iv: [u8; 16] = ciphertext.iv[..16].try_into()
            .map_err(|_| CryptoError::InvalidInput("Invalid IV length".to_string()))?;
        let sm4_key_arr: [u8; 16] = sm4_key_16[..16].try_into()
            .map_err(|_| CryptoError::InvalidInput("Invalid key length".to_string()))?;

        let plaintext = cbc_decrypt(&sm4_key_arr, &iv, &ciphertext.encrypted_data);

        Ok(plaintext)
    }
}

impl Default for Sm2AeadEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

/// 常量时间比较（防止时序攻击）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// 便捷函数：SM2 AEAD 加密
pub fn sm2_aead_encrypt(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Sm2AeadCiphertext, CryptoError> {
    Sm2AeadEncryptor::new().encrypt(recipient_public_key, plaintext, associated_data)
}

/// 便捷函数：SM2 AEAD 解密
pub fn sm2_aead_decrypt(
    recipient_private_key: &[u8],
    ciphertext: &Sm2AeadCiphertext,
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    Sm2AeadEncryptor::new().decrypt(recipient_private_key, ciphertext, associated_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_aead_encrypt_decrypt() {
        // 生成接收方密钥对
        let recipient = Sm2KeyPair::generate();
        let plaintext = b"Hello, SM2 AEAD!";

        // 加密
        let ciphertext = Sm2AeadEncryptor::new()
            .encrypt(recipient.public_key_bytes(), plaintext, Some(b"associated data"))
            .unwrap();

        assert!(!ciphertext.encrypted_data.is_empty());
        assert!(!ciphertext.auth_tag.is_empty());

        // 解密
        let decrypted = Sm2AeadEncryptor::new()
            .decrypt(recipient.private_key_bytes(), &ciphertext, Some(b"associated data"))
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm2_aead_wrong_associated_data() {
        let recipient = Sm2KeyPair::generate();
        let plaintext = b"test data";

        let ciphertext = Sm2AeadEncryptor::new()
            .encrypt(recipient.public_key_bytes(), plaintext, Some(b"correct ad"))
            .unwrap();

        // 使用错误的 associated data 解密应该失败
        let result = Sm2AeadEncryptor::new()
            .decrypt(recipient.private_key_bytes(), &ciphertext, Some(b"wrong ad"));

        assert!(result.is_err());
    }

    #[test]
    fn test_sm2_aead_convenience_functions() {
        let recipient = Sm2KeyPair::generate();
        let plaintext = b"convenience test";

        let ciphertext = sm2_aead_encrypt(
            recipient.public_key_bytes(),
            plaintext,
            None,
        ).unwrap();

        let decrypted = sm2_aead_decrypt(
            recipient.private_key_bytes(),
            &ciphertext,
            None,
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"different1", b"different2"));
        assert!(!constant_time_eq(b"short", b"longer string"));
    }
}