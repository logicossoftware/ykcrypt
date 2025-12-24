# ykcrypt File Format Specification

This document describes the file format used by ykcrypt for encrypted files.

## Overview

ykcrypt supports two file format versions:
- **YKCRYPT1**: Single recipient (legacy format)
- **YKCRYPT2**: Multiple recipients with metadata support

Both formats use:
- **ECDH key agreement** with P-256 or P-384 curves
- **ChaCha20-Poly1305** or **AES-256-GCM** for symmetric encryption
- **HKDF-SHA256** for key derivation
- **Argon2id** for optional passphrase-based key strengthening

## YKCRYPT1 Format (Single Recipient)

### Header Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Magic | `"YKCRYPT1"` (ASCII) |
| 8 | 1 | Version | Format version (currently `1`) |
| 9 | 1 | CurveID | Elliptic curve identifier |
| 10 | 1 | CipherID | Symmetric cipher identifier |
| 11 | 4 | SlotKey | PIV slot key (little-endian) |
| 15 | 1 | Flags | Feature flags |
| 16 | 2+N | EphPub | Length-prefixed ephemeral public key |
| ... | 2+16 | Salt | Length-prefixed HKDF salt (16 bytes) |
| ... | 2+N | PassSalt | Length-prefixed passphrase salt (0 or 16 bytes) |
| ... | 2+N | NoncePrefix | Length-prefixed nonce prefix |
| ... | 4 | ChunkSize | Plaintext chunk size (little-endian) |
| ... | 12 | WrapNonce | Key wrapping nonce |
| ... | 2+48 | WrappedKey | Length-prefixed wrapped file key |

### Length-Prefixed Fields

Variable-length fields are encoded as:
- 2-byte little-endian length
- N bytes of data

### Curve Identifiers

| ID | Curve | Public Key Size |
|----|-------|-----------------|
| 1 | P-256 (secp256r1) | 65 bytes (uncompressed) |
| 2 | P-384 (secp384r1) | 97 bytes (uncompressed) |

### Cipher Identifiers

| ID | Cipher | Nonce Size | Nonce Prefix Size |
|----|--------|------------|-------------------|
| 1 | XChaCha20-Poly1305 | 24 bytes | 16 bytes |
| 2 | AES-256-GCM | 12 bytes | 4 bytes |

### Flags

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | HasPassphrase | File was encrypted with a passphrase |

### Chunk Format

After the header, the file contains length-prefixed encrypted chunks:

| Size | Field | Description |
|------|-------|-------------|
| 4 | Length | Chunk ciphertext length (little-endian) |
| N | Ciphertext | Encrypted chunk + auth tag |

The file ends with a zero-length marker (4 bytes of zeros).

### Chunk Nonces

Chunk nonces are constructed as:
- **XChaCha20**: `NoncePrefix (16 bytes) || ChunkIndex (8 bytes big-endian)`
- **AES-GCM**: `NoncePrefix (4 bytes) || ChunkIndex (8 bytes big-endian)`

### Key Derivation

1. Perform ECDH: `SharedSecret = ECDH(EphemeralPrivate, RecipientPublic)`
2. Derive wrap key: `WrapKey = HKDF-SHA256(SharedSecret, Salt, "ykcrypt wrap v1")`
3. If passphrase used:
   - Derive passphrase key: `PassKey = Argon2id(Passphrase, PassSalt, t=3, m=64MB, p=4)`
   - Combine: `FinalKey = HMAC-SHA256(PassKey, WrapKey)`
4. Unwrap file key: `FileKey = ChaCha20-Poly1305-Open(WrapKey, WrapNonce, WrappedKey, HeaderAAD)`

The `HeaderAAD` is the header bytes up to (and including) `WrapNonce`.

---

## YKCRYPT2 Format (Multiple Recipients)

### Header Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Magic | `"YKCRYPT2"` (ASCII) |
| 8 | 1 | Version | Format version (currently `2`) |
| 9 | 1 | CipherID | Symmetric cipher identifier |
| 10 | 1 | Flags | Global feature flags |
| 11 | 2+N | Metadata | Length-prefixed authenticated metadata |
| ... | 2 | NumRecipients | Number of recipient blocks |
| ... | ... | Recipients | Length-prefixed recipient blocks |
| ... | 2+N | NoncePrefix | Length-prefixed nonce prefix |
| ... | 4 | ChunkSize | Plaintext chunk size |

### Metadata Structure

| Size | Field | Description |
|------|-------|-------------|
| 2 | MetaFlags | Metadata presence flags |
| 2+N | Filename | Original filename (if MetaFlags & 0x01) |
| 8 | Timestamp | Unix timestamp (if MetaFlags & 0x02) |
| 2+N | Comment | User comment (if MetaFlags & 0x04) |

### Recipient Block Structure

Each recipient block is length-prefixed and contains:

| Size | Field | Description |
|------|-------|-------------|
| 4 | SlotKey | PIV slot key (little-endian) |
| 1 | CurveID | Elliptic curve identifier |
| 1 | Flags | Per-recipient flags |
| 2+N | EphPub | Ephemeral public key |
| 2+16 | Salt | HKDF salt |
| 2+N | PassSalt | Passphrase salt (0 or 16 bytes) |
| 12 | WrapNonce | Key wrapping nonce |
| 2+48 | WrappedKey | Wrapped file key |

### Key Unwrapping for Multi-Recipient

Each recipient has an independent key wrapping:
1. Find the matching recipient block (by slot key or trial decryption)
2. Perform ECDH with the recipient's ephemeral public key
3. Derive and unwrap as in YKCRYPT1

The `RecipientAAD` for unwrapping is: `SlotKey || CurveID || EphPub`

### Re-wrapping

To add/remove recipients without re-encrypting:
1. Decrypt using your recipient block to obtain `FileKey`
2. Add new recipient blocks by calling `WrapKeyForRecipient(FileKey, NewRecipient, Passphrase)`
3. Remove recipient blocks as needed
4. Rewrite the header with updated recipient list
5. Copy the encrypted chunks unchanged

---

## Security Considerations

### Authenticated Data

- The entire header is used as AAD for chunk encryption
- This binds the ciphertext to the header, preventing header manipulation
- Each recipient block uses its own AAD for key wrapping

### Nonce Uniqueness

- Random nonce prefix ensures uniqueness across files
- Chunk index in nonce ensures uniqueness within a file
- Maximum file size limited by chunk counter (2^64 chunks)

### Key Material

- File key is 256 bits, randomly generated
- Ephemeral ECDH keys are generated fresh for each encryption
- Each recipient gets a unique ephemeral key pair

### Passphrase Strengthening

- Argon2id with conservative parameters (3 iterations, 64MB memory)
- Unique salt per recipient prevents multi-target attacks
- Passphrase is combined with ECDH secret, not used alone

---

## Test Vectors

See [test_vectors.json](test_vectors.json) for reference implementations.

### Vector 1: Basic P-256 with ChaCha20

```
Input: "Hello, World!"
Curve: P-256
Cipher: XChaCha20-Poly1305
Passphrase: (none)
```

### Vector 2: P-384 with AES-256-GCM and Passphrase

```
Input: "Secret data"
Curve: P-384
Cipher: AES-256-GCM
Passphrase: "test-passphrase"
```

---

## Compatibility Notes

- YKCRYPT1 files can be read by any version
- YKCRYPT2 requires version 2.0+
- Unknown curve/cipher IDs should be rejected
- Future versions may add new curves/ciphers with higher IDs
