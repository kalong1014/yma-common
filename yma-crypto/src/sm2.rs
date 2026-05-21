use sm2::dsa::signature::{Signer, Verifier};
use sm2::dsa::{Signature, SigningKey, VerifyingKey};
use sm2::elliptic_curve::sec1::ToSec1Point;
use sm2::elliptic_curve::Generate;
use sm2::pke::{DecryptingKey, EncryptingKey, Mode};
use sm2::{PublicKey, SecretKey};

const DIST_ID: &str = "yma-common@default";

pub struct Sm2KeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    signing_key: SigningKey,
    decrypting_key: DecryptingKey,
}

pub struct Sm2PublicKey {
    public_key: Vec<u8>,
    verifying_key: VerifyingKey,
}

impl Sm2PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let verifying_key = VerifyingKey::from_sec1_bytes(DIST_ID, bytes)?;
        Ok(Self {
            public_key: bytes.to_vec(),
            verifying_key,
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match Signature::try_from(signature) {
            Ok(sig) => self.verifying_key.verify(message, &sig).is_ok(),
            Err(_) => false,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

impl Sm2KeyPair {
    pub fn generate() -> Self {
        let secret_key = SecretKey::generate();
        let signing_key =
            SigningKey::new(DIST_ID, &secret_key).expect("Failed to create signing key");
        let public_key_bytes = {
            let pk = secret_key.public_key();
            let point = pk.to_sec1_point(false);
            point.as_bytes().to_vec()
        };
        let decrypting_key =
            DecryptingKey::new_with_mode(secret_key.to_nonzero_scalar(), Mode::C1C2C3);

        Self {
            private_key: secret_key.to_bytes().to_vec(),
            public_key: public_key_bytes,
            signing_key,
            decrypting_key,
        }
    }

    pub fn from_private_key(private_key_bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let secret_key = SecretKey::from_slice(private_key_bytes)?;
        let signing_key =
            SigningKey::new(DIST_ID, &secret_key).expect("Failed to create signing key");
        let public_key_bytes = {
            let pk = secret_key.public_key();
            let point = pk.to_sec1_point(false);
            point.as_bytes().to_vec()
        };
        let decrypting_key =
            DecryptingKey::new_with_mode(secret_key.to_nonzero_scalar(), Mode::C1C2C3);

        Ok(Self {
            private_key: private_key_bytes.to_vec(),
            public_key: public_key_bytes,
            signing_key,
            decrypting_key,
        })
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match Signature::try_from(signature) {
            Ok(sig) => self.signing_key.verifying_key().verify(message, &sig).is_ok(),
            Err(_) => false,
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pk = PublicKey::from_sec1_bytes(&self.public_key)?;
        let encrypting_key = EncryptingKey::new_with_mode(pk, Mode::C1C2C3);
        let ciphertext = encrypting_key.encrypt(&mut sm2::elliptic_curve::common::getrandom::SysRng, plaintext)?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let plaintext = self.decrypting_key.decrypt(ciphertext)?;
        Ok(plaintext)
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }
}

pub fn sign(private_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_pair = Sm2KeyPair::from_private_key(private_key_bytes)?;
    Ok(key_pair.sign(message))
}

pub fn verify(public_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match Sm2PublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk.verify(message, signature),
        Err(_) => false,
    }
}

pub fn encrypt(public_key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pk = PublicKey::from_sec1_bytes(public_key_bytes)?;
    let encrypting_key = EncryptingKey::new_with_mode(pk, Mode::C1C2C3);
    let ciphertext = encrypting_key.encrypt(&mut sm2::elliptic_curve::common::getrandom::SysRng, plaintext)?;
    Ok(ciphertext)
}

pub fn decrypt(private_key_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_pair = Sm2KeyPair::from_private_key(private_key_bytes)?;
    key_pair.decrypt(ciphertext)
}

pub fn sign_certificate(private_key_bytes: &[u8], cert_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    sign(private_key_bytes, cert_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_sign_verify() {
        let key_pair = Sm2KeyPair::generate();
        let message = b"Hello, SM2!";
        let signature = key_pair.sign(message);
        assert!(!signature.is_empty());
        assert!(key_pair.verify(message, &signature));
    }

    #[test]
    fn test_sm2_keypair_generate_multiple() {
        let kp1 = Sm2KeyPair::generate();
        let kp2 = Sm2KeyPair::generate();
        assert_eq!(kp1.public_key_bytes().len(), 65);
        assert_eq!(kp1.private_key_bytes().len(), 32);
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_sm2_verify_wrong_signature() {
        let key_pair = Sm2KeyPair::generate();
        let random_signature = vec![0xFFu8; 64];
        assert!(!key_pair.verify(b"test", &random_signature));
    }

    #[test]
    fn test_sm2_key_export_import() {
        let key_pair = Sm2KeyPair::generate();
        let priv_bytes = key_pair.private_key_bytes().to_vec();
        let pub_bytes = key_pair.public_key_bytes().to_vec();
        let restored = Sm2KeyPair::from_private_key(&priv_bytes).unwrap();
        assert_eq!(restored.private_key_bytes(), priv_bytes);
        assert_eq!(restored.public_key_bytes().len(), 65);
        let message = b"test message";
        let signature = restored.sign(message);
        assert!(restored.verify(message, &signature));
    }

    #[test]
    fn test_sm2_public_key_from_bytes() {
        let key_pair = Sm2KeyPair::generate();
        let bytes = key_pair.public_key_bytes().to_vec();
        let pk = Sm2PublicKey::from_bytes(&bytes).unwrap();
        let message = b"test message";
        let signature = key_pair.sign(message);
        assert!(pk.verify(message, &signature));
    }

    #[test]
    fn test_sm2_free_function_sign() {
        let key_pair = Sm2KeyPair::generate();
        let signature = sign(key_pair.private_key_bytes(), b"hello").unwrap();
        assert!(verify(key_pair.public_key_bytes(), b"hello", &signature));
    }

    #[test]
    fn test_sm2_sign_certificate() {
        let key_pair = Sm2KeyPair::generate();
        let cert = b"certificate data";
        let sig = sign_certificate(key_pair.private_key_bytes(), cert).unwrap();
        assert!(verify(key_pair.public_key_bytes(), cert, &sig));
    }
}