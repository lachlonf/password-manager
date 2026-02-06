use std::fs;
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::crypto::{Encryptor, KeyDerivation};
use crate::error::{Error, Result};
use crate::models::{Database, DatabaseFile};
use crate::utils::SecureString;

/// Database manager that handles file I/O and encryption
pub struct DatabaseManager {
    path: PathBuf,
}

impl DatabaseManager {
    /// Create a new DatabaseManager for the given path
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Check if the database file exists
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Initialize a new database with the given master password
    ///
    /// Returns an error if the database already exists
    pub fn init(&self, master_password: &SecureString) -> Result<()> {
        if self.exists() {
            return Err(Error::DatabaseAlreadyExists(
                self.path.display().to_string(),
            ));
        }

        // Generate random salt
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        // Derive master key
        let kd = KeyDerivation::new()?;
        let master_key = kd.derive_key(master_password.as_bytes(), &salt)?;

        // Create empty database
        let database = Database::new();

        // Serialize database
        let plaintext = bincode::serialize(&database)?;

        // Encrypt database
        let encryptor = Encryptor::new(&master_key);
        let encrypted_data = encryptor.encrypt(&plaintext)?;

        // Create database file
        let db_file = DatabaseFile::new(salt, encrypted_data);

        // Write to disk
        let bytes = db_file.to_bytes()?;
        fs::write(&self.path, bytes)?;

        // Set file permissions to 0600 (user read/write only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&self.path, permissions)?;
        }

        Ok(())
    }

    /// Load the database with the given master password
    pub fn load(&self, master_password: &SecureString) -> Result<Database> {
        if !self.exists() {
            return Err(Error::DatabaseNotFound(self.path.display().to_string()));
        }

        // Read from disk
        let bytes = fs::read(&self.path)?;

        // Parse database file
        let db_file = DatabaseFile::from_bytes(&bytes)?;

        // Derive master key
        let kd = KeyDerivation::new()?;
        let master_key = kd.derive_key(master_password.as_bytes(), &db_file.salt)?;

        // Decrypt database
        let encryptor = Encryptor::new(&master_key);
        let plaintext = encryptor.decrypt(&db_file.encrypted_data)?;

        // Deserialize database
        let mut database: Database = bincode::deserialize(&plaintext)?;

        // Update last accessed
        database.touch();

        Ok(database)
    }

    /// Save the database with the given master password
    pub fn save(&self, database: &Database, master_password: &SecureString) -> Result<()> {
        if !self.exists() {
            return Err(Error::DatabaseNotFound(self.path.display().to_string()));
        }

        // Read existing database file to get salt
        let bytes = fs::read(&self.path)?;
        let db_file = DatabaseFile::from_bytes(&bytes)?;
        let salt = db_file.salt;

        // Derive master key
        let kd = KeyDerivation::new()?;
        let master_key = kd.derive_key(master_password.as_bytes(), &salt)?;

        // Serialize database
        let plaintext = bincode::serialize(database)?;

        // Encrypt database
        let encryptor = Encryptor::new(&master_key);
        let encrypted_data = encryptor.encrypt(&plaintext)?;

        // Create database file
        let new_db_file = DatabaseFile::new(salt, encrypted_data);

        // Write to disk
        let bytes = new_db_file.to_bytes()?;
        fs::write(&self.path, bytes)?;

        Ok(())
    }

    /// Change the master password
    pub fn change_master_password(
        &self,
        old_password: &SecureString,
        new_password: &SecureString,
    ) -> Result<()> {
        // Load database with old password
        let database = self.load(old_password)?;

        // Generate new random salt
        let mut new_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_salt);

        // Derive new master key
        let kd = KeyDerivation::new()?;
        let new_master_key = kd.derive_key(new_password.as_bytes(), &new_salt)?;

        // Serialize database
        let plaintext = bincode::serialize(&database)?;

        // Encrypt with new key
        let encryptor = Encryptor::new(&new_master_key);
        let encrypted_data = encryptor.encrypt(&plaintext)?;

        // Create new database file with new salt
        let new_db_file = DatabaseFile::new(new_salt, encrypted_data);

        // Write to disk
        let bytes = new_db_file.to_bytes()?;
        fs::write(&self.path, bytes)?;

        Ok(())
    }

    /// Get the database file path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordEntry;
    use tempfile::TempDir;

    #[test]
    fn test_init_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let manager = DatabaseManager::new(&db_path);

        let password = SecureString::from("master123");

        // Initialize database
        manager.init(&password).unwrap();
        assert!(manager.exists());

        // Load database
        let database = manager.load(&password).unwrap();
        assert_eq!(database.entries.len(), 0);
    }

    #[test]
    fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let manager = DatabaseManager::new(&db_path);

        let password = SecureString::from("master123");

        // Initialize database
        manager.init(&password).unwrap();

        // Load database
        let mut database = manager.load(&password).unwrap();

        // Add entry
        let entry = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );
        database.add_entry(entry).unwrap();

        // Save database
        manager.save(&database, &password).unwrap();

        // Load again
        let loaded = manager.load(&password).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].name, "Test");
    }

    #[test]
    fn test_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let manager = DatabaseManager::new(&db_path);

        let password = SecureString::from("master123");
        let wrong_password = SecureString::from("wrong");

        // Initialize database
        manager.init(&password).unwrap();

        // Try to load with wrong password
        assert!(manager.load(&wrong_password).is_err());
    }

    #[test]
    fn test_change_master_password() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let manager = DatabaseManager::new(&db_path);

        let old_password = SecureString::from("old123");
        let new_password = SecureString::from("new456");

        // Initialize and add data
        manager.init(&old_password).unwrap();
        let mut database = manager.load(&old_password).unwrap();
        let entry = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );
        database.add_entry(entry).unwrap();
        manager.save(&database, &old_password).unwrap();

        // Change password
        manager
            .change_master_password(&old_password, &new_password)
            .unwrap();

        // Old password should not work
        assert!(manager.load(&old_password).is_err());

        // New password should work
        let loaded = manager.load(&new_password).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].name, "Test");
    }
}
