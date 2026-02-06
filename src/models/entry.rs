use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::SecureString;

/// A password entry in the database
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntry {
    /// Unique identifier for this entry
    pub id: String,
    /// User-friendly name for this entry
    pub name: String,
    /// Account username or email
    pub username: String,
    /// Encrypted password (zeroized on drop)
    pub password: SecureString,
    /// Optional associated website URL
    pub url: Option<String>,
    /// Optional additional notes
    pub notes: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub modified_at: DateTime<Utc>,
}

impl PasswordEntry {
    /// Create a new password entry
    pub fn new(name: String, username: String, password: SecureString) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            username,
            password,
            url: None,
            notes: None,
            tags: Vec::new(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Create a new password entry with all fields
    pub fn new_with_details(
        name: String,
        username: String,
        password: SecureString,
        url: Option<String>,
        notes: Option<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            username,
            password,
            url,
            notes,
            tags,
            created_at: now,
            modified_at: now,
        }
    }

    /// Update the password for this entry
    pub fn update_password(&mut self, new_password: SecureString) {
        self.password = new_password;
        self.modified_at = Utc::now();
    }

    /// Update the username for this entry
    pub fn update_username(&mut self, new_username: String) {
        self.username = new_username;
        self.modified_at = Utc::now();
    }

    /// Update the URL for this entry
    pub fn update_url(&mut self, new_url: Option<String>) {
        self.url = new_url;
        self.modified_at = Utc::now();
    }

    /// Update the notes for this entry
    pub fn update_notes(&mut self, new_notes: Option<String>) {
        self.notes = new_notes;
        self.modified_at = Utc::now();
    }

    /// Update the tags for this entry
    pub fn update_tags(&mut self, new_tags: Vec<String>) {
        self.tags = new_tags;
        self.modified_at = Utc::now();
    }

    /// Check if entry name or username matches the search query (case-insensitive)
    pub fn matches_search(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        self.name.to_lowercase().contains(&query_lower)
            || self.username.to_lowercase().contains(&query_lower)
    }

    /// Check if entry has the specified tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_entry() {
        let entry = PasswordEntry::new(
            "GitHub".to_string(),
            "user@example.com".to_string(),
            SecureString::from("password123"),
        );

        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.username, "user@example.com");
        assert!(!entry.id.is_empty());
        assert!(entry.url.is_none());
        assert!(entry.notes.is_none());
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_update_password() {
        let mut entry = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("old"),
        );

        let old_modified = entry.modified_at;
        std::thread::sleep(std::time::Duration::from_millis(1));

        entry.update_password(SecureString::from("new"));

        assert_eq!(entry.password.as_bytes(), b"new");
        assert!(entry.modified_at > old_modified);
    }

    #[test]
    fn test_matches_search() {
        let entry = PasswordEntry::new(
            "GitHub Account".to_string(),
            "user@example.com".to_string(),
            SecureString::from("pass"),
        );

        assert!(entry.matches_search("github"));
        assert!(entry.matches_search("GITHUB"));
        assert!(entry.matches_search("user"));
        assert!(entry.matches_search("example.com"));
        assert!(!entry.matches_search("gitlab"));
    }

    #[test]
    fn test_has_tag() {
        let mut entry = PasswordEntry::new(
            "Test".to_string(),
            "user".to_string(),
            SecureString::from("pass"),
        );
        entry.tags = vec!["dev".to_string(), "work".to_string()];

        assert!(entry.has_tag("dev"));
        assert!(entry.has_tag("DEV"));
        assert!(entry.has_tag("work"));
        assert!(!entry.has_tag("personal"));
    }
}
