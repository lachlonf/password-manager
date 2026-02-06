use rand::Rng;

use crate::error::{Error, Result};
use crate::utils::SecureString;

const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
const NUMBERS: &[u8] = b"0123456789";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Password generation options
pub struct PasswordGenerator {
    length: usize,
    use_symbols: bool,
    use_numbers: bool,
}

impl PasswordGenerator {
    /// Create a new password generator with the given options
    pub fn new(length: usize, use_symbols: bool, use_numbers: bool) -> Result<Self> {
        if length == 0 {
            return Err(Error::InvalidPassword(
                "Password length must be greater than 0".to_string(),
            ));
        }

        if length > 1024 {
            return Err(Error::InvalidPassword(
                "Password length must be 1024 or less".to_string(),
            ));
        }

        Ok(Self {
            length,
            use_symbols,
            use_numbers,
        })
    }

    /// Generate a secure random password
    pub fn generate(&self) -> Result<SecureString> {
        let mut charset = Vec::new();

        // Always include letters
        charset.extend_from_slice(LOWERCASE);
        charset.extend_from_slice(UPPERCASE);

        if self.use_numbers {
            charset.extend_from_slice(NUMBERS);
        }

        if self.use_symbols {
            charset.extend_from_slice(SYMBOLS);
        }

        let mut rng = rand::thread_rng();
        let password: Vec<u8> = (0..self.length)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx]
            })
            .collect();

        Ok(SecureString::from_bytes(password))
    }
}

impl Default for PasswordGenerator {
    fn default() -> Self {
        Self {
            length: 20,
            use_symbols: true,
            use_numbers: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default() {
        let gen = PasswordGenerator::default();
        let password = gen.generate().unwrap();
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_generate_custom_length() {
        let gen = PasswordGenerator::new(32, true, true).unwrap();
        let password = gen.generate().unwrap();
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_no_symbols() {
        let gen = PasswordGenerator::new(20, false, true).unwrap();
        let password = gen.generate().unwrap();

        // Password should not contain symbols
        let has_symbol = password
            .as_bytes()
            .iter()
            .any(|&b| SYMBOLS.contains(&b));
        assert!(!has_symbol);
    }

    #[test]
    fn test_generate_no_numbers() {
        let gen = PasswordGenerator::new(20, true, false).unwrap();
        let password = gen.generate().unwrap();

        // Password should not contain numbers
        let has_number = password
            .as_bytes()
            .iter()
            .any(|&b| NUMBERS.contains(&b));
        assert!(!has_number);
    }

    #[test]
    fn test_generate_uniqueness() {
        let gen = PasswordGenerator::default();
        let password1 = gen.generate().unwrap();
        let password2 = gen.generate().unwrap();

        // Generated passwords should be different (extremely high probability)
        assert_ne!(password1.as_bytes(), password2.as_bytes());
    }

    #[test]
    fn test_invalid_length_zero() {
        assert!(PasswordGenerator::new(0, true, true).is_err());
    }

    #[test]
    fn test_invalid_length_too_large() {
        assert!(PasswordGenerator::new(2048, true, true).is_err());
    }
}
