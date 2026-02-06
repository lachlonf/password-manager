use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::utils::MasterKey;

/// Encrypted data structure containing nonce and ciphertext
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedData {
    /// 96-bit (12-byte) nonce for AES-GCM
    pub nonce: [u8; 12],
    /// Ciphertext including 128-bit authentication tag
    pub ciphertext: Vec<u8>,
}

/// AES-256-GCM encryptor/decryptor
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    /// Create a new Encryptor with the given master key
    pub fn new(key: &MasterKey) -> Self {
        let cipher = Aes256Gcm::new(key.as_bytes().into());
        Self { cipher }
    }

    /// Encrypt plaintext using AES-256-GCM
    ///
    /// Generates a unique random nonce for each encryption operation.
    /// Returns `EncryptedData` containing the nonce and ciphertext with auth tag.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        // Generate unique 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with authentication
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::EncryptionFailed)?;

        Ok(EncryptedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt ciphertext using AES-256-GCM
    ///
    /// Verifies the authentication tag during decryption.
    /// Returns an error if the tag is invalid (data tampered) or wrong key.
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| Error::DecryptionFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> MasterKey {
        MasterKey::new([0u8; 32])
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let encryptor = Encryptor::new(&key);

        let plaintext = b"test password";
        let encrypted = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = test_key();
        let encryptor = Encryptor::new(&key);

        let plaintext = b"test";
        let enc1 = encryptor.encrypt(plaintext).unwrap();
        let enc2 = encryptor.encrypt(plaintext).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(enc1.nonce, enc2.nonce);
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn test_authentication_failure() {
        let key = test_key();
        let encryptor = Encryptor::new(&key);

        let plaintext = b"test";
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        encrypted.ciphertext[0] ^= 1;

        // Decryption should fail
        assert!(encryptor.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let key1 = MasterKey::new([0u8; 32]);
        let key2 = MasterKey::new([1u8; 32]);

        let encryptor1 = Encryptor::new(&key1);
        let encryptor2 = Encryptor::new(&key2);

        let plaintext = b"test";
        let encrypted = encryptor1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        assert!(encryptor2.decrypt(&encrypted).is_err());
    }
}
