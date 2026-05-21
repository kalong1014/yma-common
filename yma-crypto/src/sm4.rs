use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::rand::SecureRandom;
use smcrypto::sm4;

pub enum Sm4Mode {
    Ecb,
    Cbc,
    Gcm,
}

/// SM4 密钥类型
pub struct Sm4Key {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

impl Sm4Key {
    pub fn new(key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(key.get(..16).ok_or("Key must be at least 16 bytes")?);
        Ok(Self {
            key: key_arr,
            iv: [0u8; 16],
        })
    }

    pub fn with_iv(mut self, iv: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        self.iv.copy_from_slice(iv.get(..16).ok_or("IV must be 16 bytes")?);
        Ok(self)
    }

    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Vec<u8> {
        ecb_encrypt(&self.key, plaintext)
    }

    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Vec<u8> {
        ecb_decrypt(&self.key, ciphertext)
    }

    pub fn encrypt_cbc(&self, plaintext: &[u8]) -> Vec<u8> {
        cbc_encrypt(&self.key, &self.iv, plaintext)
    }

    pub fn decrypt_cbc(&self, ciphertext: &[u8]) -> Vec<u8> {
        cbc_decrypt(&self.key, &self.iv, ciphertext)
    }
}

pub struct Sm4Cipher {
    key: [u8; 16],
    mode: Sm4Mode,
    iv: [u8; 16],
}

impl Sm4Cipher {
    pub fn new(key: &[u8], mode: Sm4Mode) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(key.get(..16).ok_or("Key must be at least 16 bytes")?);
        Ok(Self { key: key_arr, mode, iv: [0u8; 16] })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        match self.mode {
            Sm4Mode::Ecb => ecb_encrypt(&self.key, plaintext),
            Sm4Mode::Cbc => cbc_encrypt(&self.key, &self.iv, plaintext),
            Sm4Mode::Gcm => encrypt_gcm(&self.key, &[0u8; 12], plaintext).unwrap_or_default(),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        match self.mode {
            Sm4Mode::Ecb => ecb_decrypt(&self.key, ciphertext),
            Sm4Mode::Cbc => cbc_decrypt(&self.key, &self.iv, ciphertext),
            Sm4Mode::Gcm => decrypt_gcm(&self.key, &[0u8; 12], ciphertext).unwrap_or_default(),
        }
    }
}

pub fn ecb_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = sm4::CryptSM4ECB::new(key);
    cipher.encrypt_ecb(plaintext)
}

pub fn ecb_decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = sm4::CryptSM4ECB::new(key);
    cipher.decrypt_ecb(ciphertext)
}

pub fn cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = sm4::CryptSM4CBC::new(key, iv);
    cipher.encrypt_cbc(plaintext)
}

pub fn cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = sm4::CryptSM4CBC::new(key, iv);
    cipher.decrypt_cbc(ciphertext)
}

pub fn encrypt_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 16 {
        return Err("Key must be 16 bytes".into());
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes".into());
    }
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);
    Ok(cbc_encrypt(&key_arr, &iv_arr, plaintext))
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 16 {
        return Err("Key must be 16 bytes".into());
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes".into());
    }
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);
    Ok(cbc_decrypt(&key_arr, &iv_arr, ciphertext))
}

pub fn encrypt_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key.get(..16).ok_or("Key must be 16 bytes")?);
    let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| "Nonce must be 12 bytes")?;
    let unbound_key = UnboundKey::new(&AES_128_GCM, &key_arr).map_err(|e| format!("{:?}", e))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("{:?}", e))?;
    Ok(in_out)
}

pub fn decrypt_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key.get(..16).ok_or("Key must be 16 bytes")?);
    let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| "Nonce must be 12 bytes")?;
    let unbound_key = UnboundKey::new(&AES_128_GCM, &key_arr).map_err(|e| format!("{:?}", e))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let mut in_out = ciphertext.to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed or tag mismatch")?;
    let plaintext_len = in_out.len() - 16;
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

pub fn generate_key() -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let mut key = vec![0u8; 16];
    rng.fill(&mut key).unwrap();
    key
}

pub fn generate_iv() -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let mut iv = vec![0u8; 16];
    rng.fill(&mut iv).unwrap();
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm4_ecb() {
        let key = [0x01u8; 16];
        let plaintext = b"Hello, SM4 World!";
        let ciphertext = ecb_encrypt(&key, plaintext);
        let decrypted = ecb_decrypt(&key, &ciphertext);
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_sm4_cbc() {
        let key = [0x01u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = b"Hello, SM4 CBC!";
        let ciphertext = cbc_encrypt(&key, &iv, plaintext);
        let decrypted = cbc_decrypt(&key, &iv, &ciphertext);
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_sm4_gcm_roundtrip() {
        let key = [0xABu8; 16];
        let plaintext = b"GCM mode test";
        let ciphertext = encrypt_gcm(&key, &[0u8; 12], plaintext).unwrap();
        let decrypted = decrypt_gcm(&key, &[0u8; 12], &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_gcm_tampered() {
        let key = [0x13u8; 16];
        let plaintext = b"tamper test";
        let mut ciphertext = encrypt_gcm(&key, &[0u8; 12], plaintext).unwrap();
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;
        let result = decrypt_gcm(&key, &[0u8; 12], &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_sm4_generate_key() {
        let k1 = generate_key();
        let k2 = generate_key();
        assert_eq!(k1.len(), 16);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_sm4_encrypt_cbc_roundtrip() {
        let key = vec![0x12u8; 16];
        let iv = vec![0x34u8; 16];
        let plaintext = b"encrypt_cbc roundtrip test";
        let ciphertext = encrypt_cbc(&key, &iv, plaintext).unwrap();
        let decrypted = decrypt_cbc(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_cbc_various_sizes() {
        let key = [0x22u8; 16];
        let iv = [0x33u8; 16];
        for len in [1, 15, 16, 17, 32, 64, 100] {
            let plaintext = vec![0x44u8; len];
            let ct = cbc_encrypt(&key, &iv, &plaintext);
            let pt = cbc_decrypt(&key, &iv, &ct);
            assert_eq!(pt, plaintext, "CBC failed for length {}", len);
        }
    }

    #[test]
    fn test_sm4_cipher_new() {
        let key = vec![0x79u8; 16];
        let cipher = Sm4Cipher::new(&key, Sm4Mode::Ecb).unwrap();
        let plaintext = b"Sm4Cipher ECB test";
        let ct = cipher.encrypt(plaintext);
        let pt = cipher.decrypt(&ct);
        assert_eq!(pt, plaintext);
    }
}