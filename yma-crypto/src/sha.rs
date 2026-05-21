use sha2::{Digest, Sha256, Sha512};

/// SHA-256 哈希
pub fn sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// SHA-512 哈希
pub fn sha512(data: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &str, data: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// HMAC-SHA512
pub fn hmac_sha512(key: &str, data: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<sha2::Sha512>;
    let mut mac = HmacSha512::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}