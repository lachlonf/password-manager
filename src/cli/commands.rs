use std::io::{self, Write};

use crate::cli::Commands;
use crate::crypto::PasswordGenerator;
use crate::error::{Error, Result};
use crate::models::PasswordEntry;
use crate::storage::DatabaseManager;
use crate::utils::{clipboard::SecureClipboard, SecureString};

/// Execute a CLI command
pub fn execute_command(command: Commands, db_path: &str) -> Result<()> {
    // Expand tilde in database path
    let db_path = shellexpand::tilde(db_path).to_string();

    match command {
        Commands::Init { force } => init_database(&db_path, force),
        Commands::Add {
            name,
            username,
            password,
            url,
            notes,
            tags,
        } => add_entry(&db_path, name, username, password, url, notes, tags),
        Commands::Get { name, copy, show } => get_entry(&db_path, &name, copy, show),
        Commands::Update {
            name,
            username,
            password,
            url,
            notes,
            tags,
        } => update_entry(&db_path, &name, username, password, url, notes, tags),
        Commands::Delete { name, force } => delete_entry(&db_path, &name, force),
        Commands::List {
            tag,
            search,
            verbose,
        } => list_entries(&db_path, tag.as_deref(), search.as_deref(), verbose),
        Commands::Generate {
            length,
            symbols,
            numbers,
            copy,
        } => generate_password(length, symbols, numbers, copy),
        Commands::ChangeMaster => change_master_password(&db_path),
        Commands::Export { output, format } => export_database(&db_path, &output, &format),
        Commands::Import { input, format } => import_database(&db_path, &input, &format),
    }
}

/// Prompt for master password securely
fn prompt_master_password(prompt: &str) -> Result<SecureString> {
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| Error::Internal(format!("Failed to read password: {}", e)))?;
    Ok(SecureString::from_string(password))
}

/// Initialize a new database
fn init_database(db_path: &str, force: bool) -> Result<()> {
    let manager = DatabaseManager::new(db_path);

    if manager.exists() && !force {
        return Err(Error::DatabaseAlreadyExists(db_path.to_string()));
    }

    println!("Initializing new password database at {}", db_path);
    let password = prompt_master_password("Enter master password: ")?;
    let confirm = prompt_master_password("Confirm master password: ")?;

    if password.as_bytes() != confirm.as_bytes() {
        return Err(Error::InvalidPassword("Passwords do not match".to_string()));
    }

    manager.init(&password)?;
    println!("Database initialized successfully!");

    Ok(())
}

/// Add a new entry
fn add_entry(
    db_path: &str,
    name: String,
    username: String,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
) -> Result<()> {
    let manager = DatabaseManager::new(db_path);
    let master_password = prompt_master_password("Enter master password: ")?;

    let mut database = manager.load(&master_password)?;

    // Get password (prompt if not provided)
    let entry_password = if let Some(p) = password {
        SecureString::from_string(p)
    } else {
        let p = prompt_master_password("Enter password for entry: ")?;
        let confirm = prompt_master_password("Confirm password: ")?;
        if p.as_bytes() != confirm.as_bytes() {
            return Err(Error::InvalidPassword("Passwords do not match".to_string()));
        }
        p
    };

    // Create entry
    let entry = PasswordEntry::new_with_details(name.clone(), username, entry_password, url, notes, tags);

    // Add to database
    database.add_entry(entry)?;

    // Save database
    manager.save(&database, &master_password)?;

    println!("Entry '{}' added successfully!", name);

    Ok(())
}

/// Get an entry
fn get_entry(db_path: &str, name: &str, copy: bool, show: bool) -> Result<()> {
    let manager = DatabaseManager::new(db_path);
    let master_password = prompt_master_password("Enter master password: ")?;

    let database = manager.load(&master_password)?;
    let entry = database.get_entry(name)?;

    println!("Name: {}", entry.name);
    println!("Username: {}", entry.username);

    if let Some(url) = &entry.url {
        println!("URL: {}", url);
    }

    if let Some(notes) = &entry.notes {
        println!("Notes: {}", notes);
    }

    if !entry.tags.is_empty() {
        println!("Tags: {}", entry.tags.join(", "));
    }

    println!("Created: {}", entry.created_at);
    println!("Modified: {}", entry.modified_at);

    if show {
        let password_str = entry.password.as_str().map_err(|_| {
            Error::Internal("Password contains invalid UTF-8".to_string())
        })?;
        println!("Password: {}", password_str);
    } else if copy {
        let password_str = entry.password.as_str().map_err(|_| {
            Error::Internal("Password contains invalid UTF-8".to_string())
        })?;
        let mut clipboard = SecureClipboard::new(30)?;
        clipboard.copy_with_timeout(password_str)?;
        println!("Password copied to clipboard (will clear in 30 seconds)");
    } else {
        println!("Password: ********** (use --show or --copy)");
    }

    Ok(())
}

/// Update an entry
fn update_entry(
    db_path: &str,
    name: &str,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<()> {
    let manager = DatabaseManager::new(db_path);
    let master_password = prompt_master_password("Enter master password: ")?;

    let mut database = manager.load(&master_password)?;
    let entry = database.get_entry_mut(name)?;

    if let Some(new_username) = username {
        entry.update_username(new_username);
    }

    if let Some(new_password) = password {
        entry.update_password(SecureString::from_string(new_password));
    }

    if url.is_some() {
        entry.update_url(url);
    }

    if notes.is_some() {
        entry.update_notes(notes);
    }

    if let Some(new_tags) = tags {
        entry.update_tags(new_tags);
    }

    manager.save(&database, &master_password)?;

    println!("Entry '{}' updated successfully!", name);

    Ok(())
}

/// Delete an entry
fn delete_entry(db_path: &str, name: &str, force: bool) -> Result<()> {
    let manager = DatabaseManager::new(db_path);
    let master_password = prompt_master_password("Enter master password: ")?;

    let mut database = manager.load(&master_password)?;

    if !force {
        print!("Are you sure you want to delete '{}'? (y/N): ", name);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    database.delete_entry(name)?;
    manager.save(&database, &master_password)?;

    println!("Entry '{}' deleted successfully!", name);

    Ok(())
}

/// List all entries
fn list_entries(
    db_path: &str,
    tag: Option<&str>,
    search: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let manager = DatabaseManager::new(db_path);
    let master_password = prompt_master_password("Enter master password: ")?;

    let database = manager.load(&master_password)?;

    let entries: Vec<_> = match (tag, search) {
        (Some(t), Some(s)) => database
            .filter_by_tag(t)
            .into_iter()
            .filter(|e| e.matches_search(s))
            .collect(),
        (Some(t), None) => database.filter_by_tag(t),
        (None, Some(s)) => database.search_entries(s),
        (None, None) => database.list_entries().iter().collect(),
    };

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("Found {} entries:\n", entries.len());

    for entry in entries {
        println!("  {} ({})", entry.name, entry.username);

        if verbose {
            if let Some(url) = &entry.url {
                println!("    URL: {}", url);
            }
            if !entry.tags.is_empty() {
                println!("    Tags: {}", entry.tags.join(", "));
            }
            println!("    Modified: {}", entry.modified_at);
            println!();
        }
    }

    Ok(())
}

/// Generate a password
fn generate_password(length: usize, symbols: bool, numbers: bool, copy: bool) -> Result<()> {
    let generator = PasswordGenerator::new(length, symbols, numbers)?;
    let password = generator.generate()?;

    let password_str = password
        .as_str()
        .map_err(|_| Error::Internal("Generated password contains invalid UTF-8".to_string()))?;

    if copy {
        let mut clipboard = SecureClipboard::new(30)?;
        clipboard.copy_with_timeout(password_str)?;
        println!("Password generated and copied to clipboard (will clear in 30 seconds)");
    } else {
        println!("Generated password: {}", password_str);
    }

    Ok(())
}

/// Change master password
fn change_master_password(db_path: &str) -> Result<()> {
    let manager = DatabaseManager::new(db_path);

    let old_password = prompt_master_password("Enter current master password: ")?;
    let new_password = prompt_master_password("Enter new master password: ")?;
    let confirm = prompt_master_password("Confirm new master password: ")?;

    if new_password.as_bytes() != confirm.as_bytes() {
        return Err(Error::InvalidPassword("Passwords do not match".to_string()));
    }

    manager.change_master_password(&old_password, &new_password)?;

    println!("Master password changed successfully!");

    Ok(())
}

/// Export database (not implemented in MVP)
fn export_database(_db_path: &str, _output: &str, _format: &str) -> Result<()> {
    eprintln!("Export functionality not yet implemented");
    Ok(())
}

/// Import database (not implemented in MVP)
fn import_database(_db_path: &str, _input: &str, _format: &str) -> Result<()> {
    eprintln!("Import functionality not yet implemented");
    Ok(())
}
