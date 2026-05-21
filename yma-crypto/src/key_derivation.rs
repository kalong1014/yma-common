use ring::pbkdf2;
use ring::digest;
use ring::hmac;

const PBKDF2_ITERATIONS: u32 = 100_000;
const PBKDF2_KEY_LENGTH: usize = 32;
const HMAC_SHA256_KEY_LENGTH: usize = 32;

pub struct KeyDerivation;

impl KeyDerivation {
    pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: Option<u32>, key_length: Option<usize>) -> Vec<u8> {
        let iter = iterations.unwrap_or(PBKDF2_ITERATIONS);
        let len = key_length.unwrap_or(PBKDF2_KEY_LENGTH);
        let mut out = vec![0u8; len];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iter).expect("iterations must be > 0"),
            salt,
            password,
            &mut out,
        );
        out
    }

    pub fn pbkdf2_verify(password: &[u8], salt: &[u8], iterations: u32, expected: &[u8]) -> bool {
        let provided = Self::pbkdf2_sha256(password, salt, Some(iterations), Some(expected.len()));
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, expected),
            &provided,
            &provided,
        ).is_ok()
    }

    pub fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> Vec<u8> {
        let salt_key = hmac::Key::new(hmac::HMAC_SHA256, salt);
        let prk = hmac::sign(&salt_key, input_key_material);
        prk.as_ref().to_vec()
    }

    pub fn hkdf_expand(_prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(length);
        let mut previous: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while result.len() < length {
            let mut data = previous.clone();
            data.extend_from_slice(info);
            data.push(counter);
            let h = digest::digest(&digest::SHA256, &data);
            let hash_bytes = h.as_ref();
            let needed = std::cmp::min(hash_bytes.len(), length - result.len());
            result.extend_from_slice(&hash_bytes[..needed]);
            previous = hash_bytes.to_vec();
            counter += 1;
            if counter == 0 { break; }
        }
        result
    }

    pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let prk = Self::hkdf_extract(salt, ikm);
        Self::hkdf_expand(&prk, info, length)
    }

    pub fn derive_encryption_key(master_key: &[u8], context: &[u8]) -> Vec<u8> {
        Self::hkdf(b"encryption-salt-v1", master_key, context, HMAC_SHA256_KEY_LENGTH)
    }

    pub fn derive_authentication_key(master_key: &[u8], context: &[u8]) -> Vec<u8> {
        Self::hkdf(b"auth-salt-v1", master_key, context, HMAC_SHA256_KEY_LENGTH)
    }

    pub fn derive_signing_key(master_key: &[u8], context: &[u8]) -> Vec<u8> {
        Self::hkdf(b"signing-salt-v1", master_key, context, HMAC_SHA256_KEY_LENGTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_deterministic() {
        let password = b"test_password";
        let salt = b"test_salt_16bytes";
        let result1 = KeyDerivation::pbkdf2_sha256(password, salt, None, None);
        let result2 = KeyDerivation::pbkdf2_sha256(password, salt, None, None);
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_pbkdf2_different_password() {
        let a = KeyDerivation::pbkdf2_sha256(b"password1", b"salt1234", None, None);
        let b = KeyDerivation::pbkdf2_sha256(b"password2", b"salt1234", None, None);
        assert_ne!(a, b);
    }

    #[test]
    fn test_pbkdf2_verify_valid() {
        let password = b"correct_password";
        let salt = b"fixed_salt_value";
        let hash = KeyDerivation::pbkdf2_sha256(password, salt, Some(1000), Some(16));
        assert!(KeyDerivation::pbkdf2_verify(password, salt, 1000, &hash));
    }

    #[test]
    fn test_pbkdf2_verify_invalid() {
        let password = b"correct_password";
        let salt = b"fixed_salt_value";
        let hash = KeyDerivation::pbkdf2_sha256(password, salt, Some(1000), Some(16));
        assert!(!KeyDerivation::pbkdf2_verify(b"wrong_password", salt, 1000, &hash));
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input_key_material_32bytes_long!!";
        let salt = b"hkdf_test_salt_16b";
        let info = b"test_context_info";
        let r1 = KeyDerivation::hkdf(salt, ikm, info, 32);
        let r2 = KeyDerivation::hkdf(salt, ikm, info, 32);
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);
    }

    #[test]
    fn test_hkdf_vary_length() {
        let r16 = KeyDerivation::hkdf(b"salt", b"ikm", b"info", 16);
        let r32 = KeyDerivation::hkdf(b"salt", b"ikm", b"info", 32);
        assert_eq!(r16.len(), 16);
        assert_eq!(r32.len(), 32);
    }

    #[test]
    fn test_derive_encryption_key() {
        let mk = b"this_is_a_32_byte_master_key_!!!!!";
        let ctx = b"user:12345:workspace:67890";
        let k = KeyDerivation::derive_encryption_key(mk, ctx);
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn test_derive_different_purposes() {
        let mk = b"same_master_key_for_all_purposes";
        let ctx = b"same_context";
        let ek = KeyDerivation::derive_encryption_key(mk, ctx);
        let ak = KeyDerivation::derive_authentication_key(mk, ctx);
        let sk = KeyDerivation::derive_signing_key(mk, ctx);
        assert_ne!(ek, ak);
        assert_ne!(ak, sk);
        assert_ne!(ek, sk);
    }
}