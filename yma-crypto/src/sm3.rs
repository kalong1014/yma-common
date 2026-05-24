use digest::Digest;
pub use sm3::Sm3;

/// SM3 哈希器类型
pub struct Sm3Hash;

impl Sm3Hash {
    pub fn new() -> Self {
        Self
    }

    /// 计算哈希值
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        hash(data)
    }

    /// 计算哈希值并返回十六进制字符串
    pub fn hash_hex(&self, data: &[u8]) -> String {
        hash_hex(data)
    }

    /// 计算 HMAC
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac(key, data)
    }
}

impl Default for Sm3Hash {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sm3::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash(data))
}

pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use digest::KeyInit;
    type HmacSm3 = Hmac<Sm3>;
    let mut mac = HmacSm3::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().as_slice().to_vec()
}

pub struct HashChain {
    previous_hash: Vec<u8>,
}

impl HashChain {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            previous_hash: hash(seed),
        }
    }

    pub fn append(&mut self, data: &[u8]) -> Vec<u8> {
        let mut input = self.previous_hash.clone();
        input.extend_from_slice(data);
        self.previous_hash = hash(&input);
        self.previous_hash.clone()
    }

    pub fn current_hash(&self) -> &[u8] {
        &self.previous_hash
    }

    pub fn verify_chain(seed: &[u8], data_chunks: &[&[u8]]) -> Vec<u8> {
        let mut current = hash(seed);
        for chunk in data_chunks {
            let mut input = current.clone();
            input.extend_from_slice(chunk);
            current = hash(&input);
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_known_vector() {
        assert_eq!(
            hash_hex(b"abc"),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    #[test]
    fn test_sm3_hash() {
        let data = b"Hello, SM3!";
        assert_eq!(hash(data).len(), 32);
        assert_eq!(hash(data), hash(data));
    }

    #[test]
    fn test_sm3_hash_hex() {
        let result = hash_hex(b"test");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sm3_hash_empty_data() {
        let result = hash(b"");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sm3_hmac_basic() {
        let tag = hmac(b"key", b"data");
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_sm3_hmac_consistency() {
        assert_eq!(hmac(b"key", b"data"), hmac(b"key", b"data"));
    }

    #[test]
    fn test_hash_chain() {
        let seed = b"seed";
        let mut chain = HashChain::new(seed);
        let hash1 = chain.append(b"data1");
        let hash2 = chain.append(b"data2");
        assert_ne!(hash1, hash2);
        let verified = HashChain::verify_chain(seed, &[b"data1", b"data2"]);
        assert_eq!(verified, hash2);
    }

    #[test]
    fn test_hash_chain_tamper_detection() {
        let seed = b"integrity_seed";
        let original = HashChain::verify_chain(seed, &[b"data1", b"data2"]);
        let tampered = HashChain::verify_chain(seed, &[b"data1", b"data2_modified"]);
        assert_ne!(original, tampered);
    }
}