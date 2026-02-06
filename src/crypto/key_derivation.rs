use argon2::{Algorithm, Argon2, Params, Version};
use crate::error::Result;
use crate::utils::MasterKey;

/// Key derivation using Argon2id with OWASP recommended parameters
pub struct KeyDerivation {
    params: Params,
}

impl KeyDerivation {
    /// Create a new KeyDerivation instance with OWASP 2023 recommended parameters
    /// - Memory: 19 MiB (m_cost = 19456 KiB)
    /// - Iterations: 2 (t_cost)
    /// - Parallelism: 1 (p_cost)
    pub fn new() -> Result<Self> {
        let params = Params::new(
            19456,   // m_cost: 19 MiB (19456 KiB)
            2,       // t_cost: 2 iterations
            1,       // p_cost: parallelism 1
            Some(32) // output length: 32 bytes (256 bits)
        )?;

        Ok(Self { params })
    }

    /// Derive a 256-bit master key from a password and salt
    ///
    /// # Arguments
    /// * `password` - The master password as bytes
    /// * `salt` - A 32-byte (256-bit) salt
    ///
    /// # Returns
    /// A `MasterKey` containing the derived 256-bit key
    pub fn derive_key(&self, password: &[u8], salt: &[u8; 32]) -> Result<MasterKey> {
        let mut key = [0u8; 32];

        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            self.params.clone(),
        );

        argon2.hash_password_into(password, salt, &mut key)?;

        Ok(MasterKey::new(key))
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::new().expect("Failed to create KeyDerivation with default params")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let kd = KeyDerivation::new().unwrap();
        let password = b"master password";
        let salt = [0u8; 32];

        let key1 = kd.derive_key(password, &salt).unwrap();
        let key2 = kd.derive_key(password, &salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_salt_sensitivity() {
        let kd = KeyDerivation::new().unwrap();
        let password = b"master password";
        let salt1 = [0u8; 32];
        let mut salt2 = [0u8; 32];
        salt2[0] = 1;

        let key1 = kd.derive_key(password, &salt1).unwrap();
        let key2 = kd.derive_key(password, &salt2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_password_sensitivity() {
        let kd = KeyDerivation::new().unwrap();
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = [0u8; 32];

        let key1 = kd.derive_key(password1, &salt).unwrap();
        let key2 = kd.derive_key(password2, &salt).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
