pub mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pwm")]
#[command(about = "A secure CLI password manager", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Path to password database
    #[arg(short, long, env = "PASSWORD_DB_PATH", default_value = "~/.passwords.db")]
    pub database: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new password database
    Init {
        /// Force overwrite if exists
        #[arg(short, long)]
        force: bool,
    },

    /// Add a new password entry
    Add {
        /// Name for this entry
        #[arg(short, long)]
        name: String,

        /// Username or email
        #[arg(short, long)]
        username: String,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Associated URL
        #[arg(long)]
        url: Option<String>,

        /// Notes
        #[arg(long)]
        notes: Option<String>,

        /// Tags (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Get a password entry
    Get {
        /// Name or ID of entry
        name: String,

        /// Copy password to clipboard
        #[arg(short, long)]
        copy: bool,

        /// Show password in terminal
        #[arg(short, long)]
        show: bool,
    },

    /// Update an existing entry
    Update {
        /// Name or ID of entry
        name: String,

        /// New username
        #[arg(short, long)]
        username: Option<String>,

        /// New password
        #[arg(short, long)]
        password: Option<String>,

        /// New URL
        #[arg(long)]
        url: Option<String>,

        /// New notes
        #[arg(long)]
        notes: Option<String>,

        /// New tags (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        tags: Option<Vec<String>>,
    },

    /// Delete an entry
    Delete {
        /// Name or ID of entry
        name: String,

        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// List all entries
    List {
        /// Filter by tag
        #[arg(short, long)]
        tag: Option<String>,

        /// Search by name/username
        #[arg(short, long)]
        search: Option<String>,

        /// Show detailed view
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate a secure password
    Generate {
        /// Password length
        #[arg(short, long, default_value = "20")]
        length: usize,

        /// Include symbols
        #[arg(long, default_value = "true")]
        symbols: bool,

        /// Include numbers
        #[arg(long, default_value = "true")]
        numbers: bool,

        /// Copy to clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// Change master password
    ChangeMaster,

    /// Export database (WARNING: unencrypted)
    Export {
        /// Output file path
        #[arg(short, long)]
        output: String,

        /// Export format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Import entries from file
    Import {
        /// Input file path
        #[arg(short, long)]
        input: String,

        /// Import format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}
