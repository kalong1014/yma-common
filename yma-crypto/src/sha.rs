use ring::digest::{SHA256, SHA512, Context};

/// SHA-256 哈希
pub fn sha256(data: &str) -> String {
    hex::encode(Context::new(&SHA256).update(data.as_bytes()).finish().as_ref())
}

/// SHA-512 哈希
pub fn sha512(data: &str) -> String {
    hex::encode(Context::new(&SHA512).update(data.as_bytes()).finish().as_ref())
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &str, data: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_bytes());
    hex::encode(ring::hmac::sign(&key, data.as_bytes()).as_ref())
}

/// HMAC-SHA512
pub fn hmac_sha512(key: &str, data: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key.as_bytes());
    hex::encode(ring::hmac::sign(&key, data.as_bytes()).as_ref())
}