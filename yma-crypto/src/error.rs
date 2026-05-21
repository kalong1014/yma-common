//! yma-crypto::error — 统一错误类型

use thiserror::Error;

/// 加密模块统一错误
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("SM2 error: {0}")]
    Sm2Error(String),
    #[error("SM3 error: {0}")]
    Sm3Error(String),
    #[error("SM4 error: {0}")]
    Sm4Error(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Random generation failed: {0}")]
    RandomError(String),
    #[error("E2E encryption error: {0}")]
    E2eError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<Box<dyn std::error::Error>> for CryptoError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        CryptoError::Internal(err.to_string())
    }
}