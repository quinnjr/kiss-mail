# Contributing to KISS Mail

First off, thank you for considering contributing to KISS Mail! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [KISS Philosophy](#kiss-philosophy)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please be respectful and constructive in all interactions.

## KISS Philosophy

KISS Mail follows the **"Keep It Simple, Stupid"** philosophy. When contributing, please keep in mind:

- ✅ **Simplicity over complexity** - Prefer straightforward solutions
- ✅ **Fewer dependencies** - Only add dependencies when absolutely necessary
- ✅ **Single binary** - Everything should compile into one executable
- ✅ **Zero configuration** - Things should work out of the box
- ✅ **Clear code** - Code should be readable without extensive comments

Before proposing a new feature, ask yourself:
1. Is this necessary for a basic email server?
2. Can this be done more simply?
3. Does this add significant complexity?

## Getting Started

### Prerequisites

- **Rust**: 1.94.0 or later (Rust 2024 edition)
- **Git**: For version control
- **Docker** (optional): For testing containerized builds

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/kiss-mail.git
cd kiss-mail
git remote add upstream https://github.com/quinnjr/kiss-mail.git
```

## Development Setup

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets --all-features
```

### Recommended Tools

```bash
# Install useful development tools
cargo install cargo-watch  # Auto-rebuild on changes
cargo install cargo-audit  # Security audit
cargo install cargo-llvm-cov  # Code coverage
```

### Watch Mode

```bash
# Auto-rebuild on file changes
cargo watch -x build -x test
```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-oauth-support`
- `fix/smtp-connection-timeout`
- `docs/update-readme`
- `refactor/simplify-user-auth`

### Development Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b feature/your-feature
   ```

2. **Make your changes** following the code style guidelines

3. **Test your changes**:
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```

4. **Commit your changes** following commit guidelines

5. **Push and create a PR**:
   ```bash
   git push origin feature/your-feature
   ```

## Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style (formatting, semicolons, etc.) |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `test` | Adding/updating tests |
| `chore` | Maintenance tasks |
| `ci` | CI/CD changes |
| `security` | Security improvements |

### Examples

```
feat(smtp): add STARTTLS support

fix(imap): handle connection timeout gracefully

docs: update installation instructions

refactor(crypto): simplify key derivation logic
```

### Guidelines

- Use present tense ("add feature" not "added feature")
- Use imperative mood ("move cursor to..." not "moves cursor to...")
- Keep the first line under 72 characters
- Reference issues in the footer: `Fixes #123`

## Pull Request Process

1. **Ensure your PR**:
   - Has a clear title and description
   - Links to related issues
   - Includes tests for new functionality
   - Passes all CI checks

2. **PR Checklist**:
   - [ ] Tests pass (`cargo test`)
   - [ ] No warnings (`cargo clippy`)
   - [ ] Code formatted (`cargo fmt`)
   - [ ] Documentation updated (if needed)
   - [ ] CHANGELOG updated (for significant changes)

3. **Review Process**:
   - PRs require at least one approval
   - Address review feedback promptly
   - Keep PRs focused and reasonably sized

4. **After Merge**:
   - Delete your branch
   - Update your fork:
     ```bash
     git checkout main
     git pull upstream main
     git push origin main
     ```

## Code Style

### Rust Guidelines

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting
- Address all `clippy` warnings
- Prefer `Result` over `panic!` for error handling

### File Organization

```
src/
├── main.rs          # Entry point, CLI, server orchestration
├── smtp.rs          # SMTP server implementation
├── imap.rs          # IMAP server implementation
├── pop3.rs          # POP3 server implementation
├── storage.rs       # Email storage
├── users.rs         # User management
├── crypto.rs        # Encryption
├── ...
```

### Naming Conventions

- **Files**: `snake_case.rs`
- **Modules**: `snake_case`
- **Types**: `PascalCase`
- **Functions**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`

### Error Handling

```rust
// Good: Return Result with descriptive error
pub async fn send_email(&self, email: &Email) -> Result<(), SendError> {
    // ...
}

// Avoid: panic! in library code
pub fn send_email(&self, email: &Email) {
    // panic! should be avoided
}
```

### Documentation

```rust
/// Encrypts an email for the specified recipient.
///
/// # Arguments
///
/// * `recipient` - The username of the recipient
/// * `plaintext` - The email content to encrypt
///
/// # Returns
///
/// The encrypted email or an error if encryption fails.
///
/// # Example
///
/// ```rust
/// let encrypted = crypto.encrypt_email("alice", b"Hello!").await?;
/// ```
pub async fn encrypt_email(&self, recipient: &str, plaintext: &[u8]) -> Result<EncryptedEmail, CryptoError>
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run tests for specific module
cargo test crypto::

# Generate coverage report
cargo llvm-cov --html
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_feature_works() {
        // Arrange
        let manager = CryptoManager::new(temp_dir());

        // Act
        let result = manager.generate_keypair("alice", "password").await;

        // Assert
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_error_case() {
        // Test error handling
        let result = manager.unlock_keys("nonexistent", "pass").await;
        assert!(matches!(result, Err(CryptoError::KeyNotFound(_))));
    }
}
```

### Test Guidelines

- Use descriptive test names
- Test both success and error cases
- Use `tempfile` for filesystem tests
- Mock external services when possible

## Documentation

### Code Documentation

- Document all public APIs
- Include examples for complex functions
- Explain non-obvious implementation details

### README Updates

Update the README when:
- Adding new features
- Changing configuration options
- Modifying CLI commands
- Updating deployment methods

### Changelog

For significant changes, update CHANGELOG.md:

```markdown
## [Unreleased]

### Added
- New encryption feature (#123)

### Changed
- Improved SMTP performance

### Fixed
- Fixed connection timeout issue (#456)
```

## CI Action Pins

Every GitHub Action is pinned to a full commit SHA, with the version in a
trailing comment. Dependabot updates tagged actions, but
`dtolnay/rust-toolchain` has no release tags, so Dependabot can't track it.
All workflows use one pin of its `master` branch and pick the toolchain with
`with: toolchain: stable` (or `1.94.0` for the MSRV job). Re-pin it by hand
now and then, replacing the SHA everywhere at once:

```bash
git ls-remote https://github.com/dtolnay/rust-toolchain.git refs/heads/master
grep -rl 'dtolnay/rust-toolchain@' .github/workflows \
  | xargs sed -i 's|dtolnay/rust-toolchain@[0-9a-f]*|dtolnay/rust-toolchain@<new-sha>|'
```

When you bump the MSRV, update `toolchain: 1.94.0` in `ci.yml`, the Rust
builder images in `Dockerfile` and `Dockerfile.alpine`, along with
`rust-version` in `Cargo.toml`.

## Questions?

- Open a [Discussion](https://github.com/quinnjr/kiss-mail/discussions)
- Check existing issues
- Read the documentation

Thank you for contributing! 🚀
