use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure string wrapper that zeroizes its contents when dropped
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecureString {
    inner: Vec<u8>,
}

impl SecureString {
    /// Create a new SecureString from a String
    pub fn from_string(mut s: String) -> Self {
        let bytes = s.as_bytes().to_vec();
        s.zeroize();
        Self { inner: bytes }
    }

    /// Create a new SecureString from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Get a reference to the inner bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get a string representation (use sparingly, only when needed for display)
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.inner)
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::from_bytes(s.as_bytes().to_vec())
    }
}

/// A 256-bit master key wrapper that zeroizes when dropped
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) [u8; 32]);

impl MasterKey {
    /// Create a new MasterKey from a 32-byte array
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Get a reference to the inner key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for MasterKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_creation() {
        let s = SecureString::from_string("test".to_string());
        assert_eq!(s.as_bytes(), b"test");
    }

    #[test]
    fn test_secure_string_from_str() {
        let s = SecureString::from("test");
        assert_eq!(s.as_bytes(), b"test");
    }

    #[test]
    fn test_master_key_creation() {
        let key = MasterKey::new([0u8; 32]);
        assert_eq!(key.as_bytes().len(), 32);
    }
}
