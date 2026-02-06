use clap::Parser;
use password_manager::cli::{Cli, commands::execute_command};
use password_manager::error::Error;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = execute_command(cli.command, &cli.database) {
        match e {
            Error::DecryptionFailed => {
                eprintln!("Error: Incorrect master password or corrupted database");
                std::process::exit(1);
            }
            Error::EntryNotFound(name) => {
                eprintln!("Error: No entry found with name '{}'", name);
                eprintln!("Use 'pwm list' to see all entries");
                std::process::exit(1);
            }
            Error::DatabaseNotFound(path) => {
                eprintln!("Error: Database not found at {}", path);
                eprintln!("Use 'pwm init' to create a new database");
                std::process::exit(1);
            }
            _ => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
