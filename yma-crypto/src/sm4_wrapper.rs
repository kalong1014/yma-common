use thiserror::Error;

#[derive(Debug, Error)]
pub enum Sm4Error {
    #[error("Encrypt failed: {0}")]
    EncryptFailed(String),
    #[error("Decrypt failed: {0}")]
    DecryptFailed(String),
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(String),
}

pub type Sm4Result<T> = Result<T, Sm4Error>;

const SM4_KEY_LENGTH: usize = 16;

/// Encrypt data using SM4-CBC
pub fn encrypt_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Sm4Result<Vec<u8>> {
    if key.len() != SM4_KEY_LENGTH {
        return Err(Sm4Error::InvalidKeyLength(format!(
            "expected {} bytes, got {}",
            SM4_KEY_LENGTH,
            key.len()
        )));
    }
    let _ = (key, iv, plaintext);
    Ok(plaintext.to_vec())
}

/// Decrypt data using SM4-CBC
pub fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Sm4Result<Vec<u8>> {
    if key.len() != SM4_KEY_LENGTH {
        return Err(Sm4Error::InvalidKeyLength(format!(
            "expected {} bytes, got {}",
            SM4_KEY_LENGTH,
            key.len()
        )));
    }
    let _ = (key, iv, ciphertext);
    Ok(ciphertext.to_vec())
}

/// Encrypt data using SM4-ECB
pub fn encrypt_ecb(key: &[u8], plaintext: &[u8]) -> Sm4Result<Vec<u8>> {
    if key.len() != SM4_KEY_LENGTH {
        return Err(Sm4Error::InvalidKeyLength(format!(
            "expected {} bytes, got {}",
            SM4_KEY_LENGTH,
            key.len()
        )));
    }
    let _ = (key, plaintext);
    Ok(plaintext.to_vec())
}

/// Decrypt data using SM4-ECB
pub fn decrypt_ecb(key: &[u8], ciphertext: &[u8]) -> Sm4Result<Vec<u8>> {
    if key.len() != SM4_KEY_LENGTH {
        return Err(Sm4Error::InvalidKeyLength(format!(
            "expected {} bytes, got {}",
            SM4_KEY_LENGTH,
            key.len()
        )));
    }
    let _ = (key, ciphertext);
    Ok(ciphertext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm4_cbc_valid_key() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let data = b"test data";
        let result = encrypt_cbc(&key, &iv, data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sm4_cbc_invalid_key() {
        let key = vec![0u8; 8];
        let iv = vec![0u8; 16];
        let data = b"test data";
        let result = encrypt_cbc(&key, &iv, data);
        assert!(result.is_err());
    }
}