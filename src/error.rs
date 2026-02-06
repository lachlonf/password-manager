use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Cryptographic errors
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed - incorrect master password or corrupted data")]
    DecryptionFailed,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    // Storage errors
    #[error("Database not found at path: {0}")]
    DatabaseNotFound(String),

    #[error("Database already exists at path: {0}")]
    DatabaseAlreadyExists(String),

    #[error("Invalid database file format")]
    InvalidFileFormat,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    // Entry errors
    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Duplicate entry name: {0}")]
    DuplicateEntry(String),

    // Validation errors
    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    // Clipboard errors
    #[error("Clipboard error: {0}")]
    ClipboardError(String),

    // Serialization errors
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),

    // Argon2 errors
    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    // Generic
    #[error("Internal error: {0}")]
    Internal(String),
}

// Implement From for argon2::Error
impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Self {
        Error::Argon2Error(err.to_string())
    }
}

// Implement From for argon2::password_hash::Error
impl From<argon2::password_hash::Error> for Error {
    fn from(err: argon2::password_hash::Error) -> Self {
        Error::KeyDerivationFailed(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
