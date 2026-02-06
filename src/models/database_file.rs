use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::EncryptedData;
use crate::error::{Error, Result};
use crate::models::entry::PasswordEntry;

/// Top-level database file structure
#[derive(Serialize, Deserialize)]
pub struct DatabaseFile {
    /// File format version for future compatibility
    pub version: u32,
    /// Salt for Argon2 key derivation (256 bits)
    pub salt: [u8; 32],
    /// Encrypted database content (contains nonce + ciphertext + auth tag)
    pub encrypted_data: EncryptedData,
}

impl DatabaseFile {
    pub const CURRENT_VERSION: u32 = 1;
    pub const MAGIC_BYTES: &'static [u8; 4] = b"PWDB";

    /// Create a new DatabaseFile
    pub fn new(salt: [u8; 32], encrypted_data: EncryptedData) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            salt,
            encrypted_data,
        }
    }

    /// Convert DatabaseFile to bytes for writing to disk
    ///
    /// Binary format:
    /// [0-3]   Magic bytes: "PWDB"
    /// [4-7]   Version: u32 (little-endian)
    /// [8-39]  Salt: 32 bytes
    /// [40-51] Nonce: 12 bytes
    /// [52-55] Ciphertext length: u32 (little-endian)
    /// [56-n]  Ciphertext + 16-byte auth tag
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Magic bytes
        bytes.extend_from_slice(Self::MAGIC_BYTES);

        // Version
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Salt
        bytes.extend_from_slice(&self.salt);

        // Nonce
        bytes.extend_from_slice(&self.encrypted_data.nonce);

        // Ciphertext length
        bytes.extend_from_slice(&(self.encrypted_data.ciphertext.len() as u32).to_le_bytes());

        // Ciphertext
        bytes.extend_from_slice(&self.encrypted_data.ciphertext);

        Ok(bytes)
    }

    /// Parse DatabaseFile from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 56 {
            return Err(Error::InvalidFileFormat);
        }

        // Validate magic bytes
        if &bytes[0..4] != Self::MAGIC_BYTES {
            return Err(Error::InvalidFileFormat);
        }

        // Parse version
        let version = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| Error::InvalidFileFormat)?,
        );

        // Parse salt
        let salt: [u8; 32] = bytes[8..40]
            .try_into()
            .map_err(|_| Error::InvalidFileFormat)?;

        // Parse nonce
        let nonce: [u8; 12] = bytes[40..52]
            .try_into()
            .map_err(|_| Error::InvalidFileFormat)?;

        // Parse ciphertext length
        let ct_len = u32::from_le_bytes(
            bytes[52..56]
                .try_into()
                .map_err(|_| Error::InvalidFileFormat)?,
        ) as usize;

        // Verify we have enough bytes
        if bytes.len() < 56 + ct_len {
            return Err(Error::InvalidFileFormat);
        }

        // Parse ciphertext
        let ciphertext = bytes[56..56 + ct_len].to_vec();

        Ok(Self {
            version,
            salt,
            encrypted_data: EncryptedData { nonce, ciphertext },
        })
    }
}

/// Internal database structure (encrypted)
#[derive(Serialize, Deserialize)]
pub struct Database {
    /// All password entries
    pub entries: Vec<PasswordEntry>,
    /// Database metadata
    pub metadata: DatabaseMetadata,
}

impl Database {
    /// Create a new empty database
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            entries: Vec::new(),
            metadata: DatabaseMetadata {
                created_at: now,
                last_accessed: now,
                entry_count: 0,
            },
        }
    }

    /// Add a new entry to the database
    pub fn add_entry(&mut self, entry: PasswordEntry) -> Result<()> {
        // Check for duplicate names
        if self.entries.iter().any(|e| e.name == entry.name) {
            return Err(Error::DuplicateEntry(entry.name.clone()));
        }

        self.entries.push(entry);
        self.metadata.entry_count = self.entries.len();
        self.metadata.last_accessed = Utc::now();

        Ok(())
    }

    /// Get an entry by name or ID
    pub fn get_entry(&self, name_or_id: &str) -> Result<&PasswordEntry> {
        self.entries
            .iter()
            .find(|e| e.name == name_or_id || e.id == name_or_id)
            .ok_or_else(|| Error::EntryNotFound(name_or_id.to_string()))
    }

    /// Get a mutable entry by name or ID
    pub fn get_entry_mut(&mut self, name_or_id: &str) -> Result<&mut PasswordEntry> {
        self.metadata.last_accessed = Utc::now();
        self.entries
            .iter_mut()
            .find(|e| e.name == name_or_id || e.id == name_or_id)
            .ok_or_else(|| Error::EntryNotFound(name_or_id.to_string()))
    }

    /// Delete an entry by name or ID
    pub fn delete_entry(&mut self, name_or_id: &str) -> Result<PasswordEntry> {
        let index = self
            .entries
            .iter()
            .position(|e| e.name == name_or_id || e.id == name_or_id)
            .ok_or_else(|| Error::EntryNotFound(name_or_id.to_string()))?;

        let entry = self.entries.remove(index);
        self.metadata.entry_count = self.entries.len();
        self.metadata.last_accessed = Utc::now();

        Ok(entry)
    }

    /// List all entries
    pub fn list_entries(&self) -> &[PasswordEntry] {
        &self.entries
    }

    /// Search entries by query
    pub fn search_entries(&self, query: &str) -> Vec<&PasswordEntry> {
        self.entries
            .iter()
            .filter(|e| e.matches_search(query))
            .collect()
    }

    /// Filter entries by tag
    pub fn filter_by_tag(&self, tag: &str) -> Vec<&PasswordEntry> {
        self.entries.iter().filter(|e| e.has_tag(tag)).collect()
    }

    /// Update last accessed timestamp
    pub fn touch(&mut self) {
        self.metadata.last_accessed = Utc::now();
    }
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}

/// Database metadata
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DatabaseMetadata {
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub entry_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::SecureString;

    #[test]
    fn test_database_file_roundtrip() {
        let salt = [42u8; 32];
        let encrypted_data = EncryptedData {
            nonce: [1u8; 12],
            ciphertext: vec![1, 2, 3, 4, 5],
        };

        let db_file = DatabaseFile::new(salt, encrypted_data);
        let bytes = db_file.to_bytes().unwrap();
        let parsed = DatabaseFile::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, DatabaseFile::CURRENT_VERSION);
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.encrypted_data.nonce, [1u8; 12]);
        assert_eq!(parsed.encrypted_data.ciphertext, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_database_add_entry() {
        let mut db = Database::new();
        let entry = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );

        db.add_entry(entry).unwrap();
        assert_eq!(db.entries.len(), 1);
        assert_eq!(db.metadata.entry_count, 1);
    }

    #[test]
    fn test_database_duplicate_entry() {
        let mut db = Database::new();
        let entry1 = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );
        let entry2 = PasswordEntry::new(
            "Test".to_string(),
            "user2".to_string(),
            SecureString::from("pass2"),
        );

        db.add_entry(entry1).unwrap();
        assert!(db.add_entry(entry2).is_err());
    }

    #[test]
    fn test_database_get_entry() {
        let mut db = Database::new();
        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );
        let entry_id = entry.id.clone();

        db.add_entry(entry).unwrap();

        // Get by name
        let found = db.get_entry("GitHub").unwrap();
        assert_eq!(found.name, "GitHub");

        // Get by ID
        let found = db.get_entry(&entry_id).unwrap();
        assert_eq!(found.name, "GitHub");
    }

    #[test]
    fn test_database_delete_entry() {
        let mut db = Database::new();
        let entry = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );

        db.add_entry(entry).unwrap();
        assert_eq!(db.entries.len(), 1);

        db.delete_entry("Test").unwrap();
        assert_eq!(db.entries.len(), 0);
        assert_eq!(db.metadata.entry_count, 0);
    }
}
