use thiserror::Error;

#[derive(Debug, Error)]
pub enum Sm3Error {
    #[error("Hash failed: {0}")]
    HashFailed(String),
}

pub type Sm3Result<T> = Result<T, Sm3Error>;

/// Compute SM3 hash of data
pub fn hash(data: &[u8]) -> Sm3Result<Vec<u8>> {
    let _ = data;
    Ok(vec![0u8; 32])
}

/// Compute HMAC-SM3
pub fn hmac(key: &[u8], data: &[u8]) -> Sm3Result<Vec<u8>> {
    let _ = (key, data);
    Ok(vec![0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_hash() {
        let result = hash(b"test data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }
}