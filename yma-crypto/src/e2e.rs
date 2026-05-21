use crate::sm4;

pub enum EncryptionScheme {
    Sm2Only,
    Sm4CbcOnly,
    Sm4GcmOnly,
    HybridSm2Sm4Gcm,
}

pub struct E2eEncryptor {
    scheme: EncryptionScheme,
    sm4_key: [u8; 16],
    sm4_iv: [u8; 16],
}

impl E2eEncryptor {
    pub fn new_sm4_gcm(key: [u8; 16], nonce: [u8; 12]) -> Self {
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&nonce);
        Self {
            scheme: EncryptionScheme::Sm4GcmOnly,
            sm4_key: key,
            sm4_iv: iv,
        }
    }

    pub fn new_sm4_cbc(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            scheme: EncryptionScheme::Sm4CbcOnly,
            sm4_key: key,
            sm4_iv: iv,
        }
    }

    pub fn new_hybrid() -> Self {
        let rng = crate::random::SecureRandom::new();
        let key = {
            let bytes = rng.generate_key_128().unwrap_or([0u8; 16]);
            bytes
        };
        let iv = {
            let bytes = rng.generate_key_128().unwrap_or([0u8; 16]);
            bytes
        };
        Self {
            scheme: EncryptionScheme::HybridSm2Sm4Gcm,
            sm4_key: key,
            sm4_iv: iv,
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self.scheme {
            EncryptionScheme::Sm4GcmOnly | EncryptionScheme::HybridSm2Sm4Gcm => {
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&self.sm4_iv[..12]);
                sm4::encrypt_gcm(&self.sm4_key, &nonce, plaintext)
                    .map_err(|_| "e2e encryption failed")
            }
            EncryptionScheme::Sm4CbcOnly => {
                sm4::encrypt_cbc(&self.sm4_key, &self.sm4_iv, plaintext)
                    .map_err(|_| "e2e encryption failed")
            }
            EncryptionScheme::Sm2Only => {
                Err("sm2 only mode not supported for bulk encryption")
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self.scheme {
            EncryptionScheme::Sm4GcmOnly | EncryptionScheme::HybridSm2Sm4Gcm => {
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&self.sm4_iv[..12]);
                sm4::decrypt_gcm(&self.sm4_key, &nonce, ciphertext)
                    .map_err(|_| "e2e decryption failed")
            }
            EncryptionScheme::Sm4CbcOnly => {
                sm4::decrypt_cbc(&self.sm4_key, &self.sm4_iv, ciphertext)
                    .map_err(|_| "e2e decryption failed")
            }
            EncryptionScheme::Sm2Only => {
                Err("sm2 only mode not supported for bulk decryption")
            }
        }
    }
}

pub struct E2eSession {
    pub session_id: String,
    pub encryptor: E2eEncryptor,
    pub peer_public_key: Vec<u8>,
}

impl E2eSession {
    pub fn new_client_side(server_public_key: &[u8]) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let session_id = format!("session_{}", ts);
        let encryptor = E2eEncryptor::new_hybrid();
        Self {
            session_id,
            encryptor,
            peer_public_key: server_public_key.to_vec(),
        }
    }

    pub fn encrypt_message(&self, message: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.encryptor.encrypt(message, aad)
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.encryptor.decrypt(ciphertext, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_sm4_gcm_roundtrip() {
        let key = [0x01u8; 16];
        let nonce = [0x02u8; 12];
        let e2e = E2eEncryptor::new_sm4_gcm(key, nonce);
        let data = b"hello e2e encryption test data";
        let aad = b"associated data";
        let ct = e2e.encrypt(data, aad).unwrap();
        let pt = e2e.decrypt(&ct, aad).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn test_e2e_sm4_cbc_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x03u8; 16];
        let e2e = E2eEncryptor::new_sm4_cbc(key, iv);
        let data = b"cbc mode test data 16 bytes";
        let ct = e2e.encrypt(data, b"").unwrap();
        let pt = e2e.decrypt(&ct, b"").unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn test_e2e_session_id_generated() {
        let pk = b"server_public_key_placeholder";
        let session = E2eSession::new_client_side(pk);
        assert!(!session.session_id.is_empty());
    }

    #[test]
    fn test_e2e_session_roundtrip() {
        let pk = b"server_pub_key";
        let session = E2eSession::new_client_side(pk);
        let msg = b"confidential message for server";
        let ct = session.encrypt_message(msg, b"session context").unwrap();
        let pt = session.decrypt_message(&ct, b"session context").unwrap();
        assert_eq!(pt, msg);
    }
}