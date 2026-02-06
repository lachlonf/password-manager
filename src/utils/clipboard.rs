use arboard::Clipboard;
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};

/// Secure clipboard manager with auto-clear timeout
pub struct SecureClipboard {
    clipboard: Clipboard,
    timeout: Duration,
}

impl SecureClipboard {
    /// Create a new SecureClipboard with timeout in seconds
    pub fn new(timeout_seconds: u64) -> Result<Self> {
        let clipboard = Clipboard::new()
            .map_err(|e| Error::ClipboardError(format!("Failed to initialize clipboard: {}", e)))?;

        Ok(Self {
            clipboard,
            timeout: Duration::from_secs(timeout_seconds),
        })
    }

    /// Copy text to clipboard and auto-clear after timeout
    ///
    /// Spawns a background thread that clears the clipboard after the timeout,
    /// but only if the clipboard still contains our text (to avoid disrupting user workflow)
    pub fn copy_with_timeout(&mut self, text: &str) -> Result<()> {
        // Copy to clipboard
        self.clipboard
            .set_text(text)
            .map_err(|e| Error::ClipboardError(format!("Failed to copy to clipboard: {}", e)))?;

        // Spawn thread to clear after timeout
        let timeout = self.timeout;
        let clear_text = text.to_string();

        thread::spawn(move || {
            thread::sleep(timeout);

            // Only clear if our text is still there
            if let Ok(mut cb) = Clipboard::new() {
                if let Ok(current) = cb.get_text() {
                    if current == clear_text {
                        let _ = cb.clear();
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_creation() {
        let clipboard = SecureClipboard::new(30);
        assert!(clipboard.is_ok());
    }

    #[test]
    fn test_copy_to_clipboard() {
        let mut clipboard = SecureClipboard::new(30).unwrap();
        let result = clipboard.copy_with_timeout("test");

        // May fail in headless environments, but should not panic
        if result.is_ok() {
            // Verify it was copied
            let mut cb = Clipboard::new().unwrap();
            let text = cb.get_text().unwrap();
            assert_eq!(text, "test");
        }
    }
}
