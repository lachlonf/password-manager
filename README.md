# Secure CLI Password Manager

A production-ready command-line password manager written in Rust with industry-standard encryption and security best practices.

## Features

- **AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **Argon2id Key Derivation**: OWASP-recommended parameters for master password protection
- **Secure Memory Handling**: Automatic zeroization of sensitive data
- **Password Generation**: Cryptographically secure random password generation
- **Clipboard Integration**: Auto-clear after timeout for security
- **Search and Filtering**: Find entries by name, username, or tags
- **Cross-platform**: Works on macOS, Linux, and Windows

## Installation

### Prerequisites

- Rust 1.70 or later

### Build from Source

```bash
# Clone the repository
git clone https://github.com/lachlonf/password-manager.git
cd password-manager

# Build the project
cargo build --release
```

The binary will be available at `target/release/pwm`.

### Install Globally

```bash
# From within the cloned directory
cargo install --path .
```

## Usage

### Initialize a New Database

```bash
pwm init
```

This creates an encrypted database at `~/.passwords.db` (customizable via `-d` flag or `PASSWORD_DB_PATH` env var).

### Add a Password Entry

```bash
# Basic entry (will prompt for password)
pwm add -n "GitHub" -u "user@example.com"

# With all details
pwm add -n "AWS" -u "admin" -p "secret123" --url "https://aws.amazon.com" -t "work,cloud"
```

### Get a Password

```bash
# Show entry details (password hidden)
pwm get GitHub

# Copy password to clipboard (auto-clears in 30 seconds)
pwm get GitHub -c

# Show password in terminal
pwm get GitHub -s
```

### List All Entries

```bash
# List all
pwm list

# Filter by tag
pwm list -t "work"

# Search by name/username
pwm list -s "github"

# Verbose output
pwm list -v
```

### Update an Entry

```bash
# Update password
pwm update GitHub -p "new-password"

# Update username and tags
pwm update GitHub -u "newuser@example.com" -t "dev,git"
```

### Delete an Entry

```bash
# With confirmation prompt
pwm delete GitHub

# Skip confirmation
pwm delete GitHub -f
```

### Generate Passwords

```bash
# Generate 20-character password (default)
pwm generate

# Custom length
pwm generate -l 32

# Copy to clipboard
pwm generate -l 32 -c

# No symbols
pwm generate --symbols false

# No numbers
pwm generate --numbers false
```

### Change Master Password

```bash
pwm change-master
```

### Use Custom Database Path

```bash
# Via flag
pwm -d ~/my-passwords.db init

# Via environment variable
export PASSWORD_DB_PATH=~/my-passwords.db
pwm init
```

## Security Features

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Nonce**: Unique 96-bit nonce per encryption operation
- **Authentication**: 128-bit authentication tag prevents tampering

### Key Derivation

- **Algorithm**: Argon2id (winner of Password Hashing Competition)
- **Parameters**: 19 MiB memory, 2 iterations, parallelism 1 (OWASP 2023 recommendations)
- **Salt**: 256-bit random salt generated on database initialization

### Memory Security

- All sensitive data (passwords, keys) implements `Zeroize` and `ZeroizeOnDrop`
- Memory is securely cleared using volatile writes when data goes out of scope
- Prevents sensitive data from lingering in memory after use

### File Storage

- Single encrypted binary file
- Magic bytes for format validation
- Unix file permissions set to 0600 (user read/write only)

### Clipboard Security

- Auto-clear after 30 seconds (configurable)
- Only clears if password still in clipboard (won't disrupt workflow)

## Threat Model

### Protected Against

- Attacker with filesystem access (encrypted at rest)
- Brute-force master password attacks (Argon2 slows attempts)
- Data tampering (GCM authentication tag detects modifications)
- Memory scraping attacks (zeroize clears sensitive data)

### Not Protected Against

- Keyloggers capturing master password during input
- Compromised operating system or hardware
- Physical attacks (coercion, etc.)
- Microarchitectural attacks (Spectre/Meltdown)

## File Format

The database file uses a custom binary format:

```
[0-3]   Magic bytes: "PWDB"
[4-7]   Version: u32 (little-endian)
[8-39]  Salt: 32 bytes (Argon2 salt)
[40-51] Nonce: 12 bytes (AES-GCM nonce)
[52-55] Ciphertext length: u32
[56-n]  Ciphertext + 16-byte auth tag
```

## Development

### Run Tests

```bash
cargo test
```

### Build with Optimizations

```bash
cargo build --release
```

The release profile is configured for maximum optimization:
- Link-time optimization (LTO)
- Single codegen unit
- Debug symbols stripped

## Dependencies

Key dependencies and their purposes:

- `aes-gcm`: RustCrypto's security-audited AES-256-GCM implementation
- `argon2`: Pure Rust Argon2 for key derivation
- `zeroize`: Secure memory clearing
- `clap`: Command-line parsing
- `arboard`: Clipboard management (maintained by 1Password)
- `bincode`: Efficient binary serialization
- `chrono`: Timestamp handling
- `rpassword`: Secure password input

## License

MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. Code follows Rust formatting guidelines (`cargo fmt`)
3. No clippy warnings (`cargo clippy`)
4. Security-sensitive changes are well-documented

## Security Considerations

- Never share your master password
- Use a strong, unique master password (minimum 16 characters recommended)
- Keep your database file backed up securely
- Report security issues responsibly

## Author

Built with Rust and security in mind.
