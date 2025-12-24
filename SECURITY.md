# SECURITY

This repository is a reference implementation to demonstrate a YubiKey PIV-backed file encryption workflow.

## Important warnings

- No formal security audit has been performed.
- Key management (PIN/PUK/management key changes), recovery, backups, and slot lifecycle are not automated.
- Device loss or slot reset means data loss.

## Implemented security features

### Multiple recipients (YKCRYPT2 format)
- Files can be encrypted for multiple recipients simultaneously
- Each recipient has independent key wrapping with unique ephemeral keys
- Recipients can be added/removed without re-encrypting the payload (via `rewrap` command)
- Supports recipient rotation for key lifecycle management

### Atomic output writes
- All file writes use atomic operations (write to temp, then rename)
- Prevents partial/corrupt files from power loss or crashes during encryption/decryption
- Original files are preserved until the operation fully completes

### Structured error classification
- Errors are categorized (YubiKey, File, Crypto, Input, Format)
- User-friendly error messages with troubleshooting hints
- Clear indication of retryable errors (e.g., touch timeout, wrong PIN)
- Detailed PIN retry information to prevent lockout

### Authenticated metadata
- Optional metadata section (filename, timestamp, comment)
- Metadata is authenticated via AAD but not encrypted
- Preserves original filename information for recovery

### File format specification
- Complete format documentation in [FORMAT.md](FORMAT.md)
- Test vectors in [test_vectors.json](test_vectors.json) for interoperability testing

## Suggested future improvements

- Hardware Security Module (HSM) support for enterprise deployments
- Integration with external key escrow/backup services
- Audit logging for compliance requirements
- Support for additional curves (P-521, Ed25519 for signing)
- Browser extension for web-based encryption/decryption
