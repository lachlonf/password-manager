use arboard::Clipboard;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Secure clipboard manager with auto-clear timeout
pub struct SecureClipboard {
    clipboard: Clipboard,
    timeout_seconds: u64,
}

impl SecureClipboard {
    /// Create a new SecureClipboard with timeout in seconds
    pub fn new(timeout_seconds: u64) -> Result<Self> {
        let clipboard = Clipboard::new()
            .map_err(|e| Error::ClipboardError(format!("Failed to initialize clipboard: {}", e)))?;

        Ok(Self {
            clipboard,
            timeout_seconds,
        })
    }

    /// Copy text to clipboard and auto-clear after timeout
    ///
    /// Spawns a detached OS process that clears the clipboard after the timeout.
    /// A separate process is needed because background threads are killed when the
    /// main process exits.
    pub fn copy_with_timeout(&mut self, text: &str) -> Result<()> {
        // Copy to clipboard
        self.clipboard
            .set_text(text)
            .map_err(|e| Error::ClipboardError(format!("Failed to copy to clipboard: {}", e)))?;

        // Spawn a detached process to clear clipboard after timeout
        Self::spawn_clear_process(self.timeout_seconds);

        Ok(())
    }

    /// Spawn a detached process that clears the clipboard after a delay
    fn spawn_clear_process(timeout_seconds: u64) {
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!("sleep {} && printf '' | pbcopy", timeout_seconds))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "sleep {} && printf '' | xclip -selection clipboard 2>/dev/null || printf '' | xsel --clipboard 2>/dev/null",
                    timeout_seconds
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_creation() {
        let clipboard = SecureClipboard::new(60);
        assert!(clipboard.is_ok());
    }

    #[test]
    fn test_copy_to_clipboard() {
        let mut clipboard = SecureClipboard::new(60).unwrap();
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
