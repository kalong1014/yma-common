//! yma-crypto 国密算法统一库
//!
//! 提供 SM2/SM3/SM4 国密算法的标准化接口
//! 版本锁定: 0.3.2

pub mod sm2;
pub mod sm3;
pub mod sm4;
pub mod sha;
pub mod sm2_aead;
pub mod key_hierarchy;
pub mod random;
pub mod key_derivation;
pub mod key_pool;
pub mod e2e;
pub mod error;

pub use key_hierarchy::KeyManager;
pub use random::{SecureRandom, Charset, generate_random_bytes, generate_random_string};
pub use key_derivation::KeyDerivation;
pub use key_pool::KeyPool;
pub use e2e::E2eEncryptor;
pub use error::CryptoError;
pub use sha::{sha256, sha512, hmac_sha256, hmac_sha512};
pub use sm3::Sm3Hash;
pub use sm4::Sm4Key;
pub use sm2_aead::{Sm2AeadEncryptor, Sm2AeadCiphertext, sm2_aead_encrypt, sm2_aead_decrypt};