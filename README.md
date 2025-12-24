# ykcrypt

`ykcrypt` is a small Go command-line tool that encrypts/decrypts files using a YubiKey PIV ECDH key agreement key as the hardware-root secret.

## Security model (high-level)

- Encryption uses ephemeral ECDH against the YubiKey slot public key:
  - Encryption can be done without the YubiKey if you have the exported recipient string (public key).
  - Decryption requires the YubiKey because the slot private key performs ECDH to recover the wrapping key.
- **Multiple recipients supported**: Files can be encrypted for multiple recipients simultaneously (YKCRYPT2 format).
- A random 32-byte file key encrypts the file content in streaming chunks (XChaCha20-Poly1305 or AES-256-GCM).
- The file key is wrapped (ChaCha20-Poly1305) under a key derived from the ECDH shared secret via HKDF-SHA256.
- Optional second factor: passphrase mixed in (Argon2id -> HMAC-SHA256) to require both YubiKey + passphrase for decryption.
- **Atomic writes**: All output files are written atomically to prevent corruption.
- **Structured errors**: Clear error messages with troubleshooting hints for common issues.

This is a reference implementation; for production use, review threat models, add recipient rotation, backups, recovery workflows, audits, etc.

## Prerequisites

- Go 1.22+ recommended (uses `crypto/ecdh`).
- PC/SC stack installed and running (Windows: built-in; Linux: pcscd/pcsc-lite; macOS: built-in).
- A YubiKey that supports the PIV applet.

**Note:** ykcrypt currently supports Windows only due to dependency on Windows Smart Card API (WinSCard) via piv-go library.

## Build

### Quick Build (Current Platform)

```powershell
# PowerShell (Windows)
.\build.ps1

# Outputs to: bin/windows/amd64/ykcrypt.exe
```

### Build with Version

```powershell
.\build.ps1 -Version "1.2.0"
```

### Build for All Windows Platforms

```powershell
.\build.ps1 -Version "1.0.0" -Platforms "all"

# Creates:
#   bin/windows/amd64/ykcrypt.exe (with version info resource)
#   bin/windows/arm64/ykcrypt.exe
```

### Build Options

- `-Version` - Version string to embed (default: auto-detect from git tags or "dev")
- `-Platforms` - Target platforms: "all", "windows/amd64", "windows/arm64", etc.
- `-Clean` - Clean build artifacts before building
- `-SkipVersionInfo` - Skip Windows version resource generation (faster builds)

The build script automatically embeds:
- Version number
- Git commit hash
- Build timestamp (UTC)
- Go version
- Windows version resource (for AMD64 builds)

### Manual Build

```bash
go mod tidy
go build -o ykcrypt.exe .
```

## Usage

### Provision a slot (generates EC key + stores a certificate containing the public key)

```bash
./ykcrypt init -slot 9d
```

This prints a recipient string of the form:

```
ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>
```

Save it somewhere safe (it is not secret, but it identifies the recipient).

### Export recipient string later

```bash
./ykcrypt export -slot 9d > recipient.txt
```

### Quick Commands (Recommended)

For everyday use, `ykcrypt` provides short commands that use sensible defaults (slot 9d, auto-detect recipient from YubiKey):

**Quick encrypt:**
```bash
# Encrypt file (creates secrets.txt.ykc)
./ykcrypt e secrets.txt

# Encrypt with custom output name
./ykcrypt e secrets.txt encrypted.ykc

# Encrypt and overwrite original file (replaces secrets.txt with encrypted version)
./ykcrypt e -F secrets.txt
```

**Quick decrypt:**
```bash
# Decrypt file (creates secrets.txt from secrets.txt.ykc)
./ykcrypt d secrets.txt.ykc

# Decrypt with custom output name
./ykcrypt d secrets.txt.ykc decrypted.txt

# Decrypt and overwrite original file (replaces encrypted file with decrypted version)
./ykcrypt d -F secrets.txt.ykc
```

You will be prompted for the PIV PIN, then touch the YubiKey when it blinks.

### Full Commands (Advanced)

For more control, use the full `encrypt` and `decrypt` commands with explicit flags:

**Encrypt:**
```bash
RECIP="$(cat recipient.txt)"
./ykcrypt encrypt -recipient "$RECIP" -in secrets.txt -out secrets.txt.ykc
```

With a passphrase as a second factor:

```bash
./ykcrypt encrypt -recipient "$RECIP" -passphrase -in secrets.txt -out secrets.txt.ykc
```

**Decrypt (requires YubiKey):**
```bash
./ykcrypt decrypt -in secrets.txt.ykc -out secrets.txt
```

You will be prompted for the PIV PIN, and for the passphrase if the ciphertext indicates one is required.

### Rewrap Command (Add/Remove Recipients)

The `rewrap` command allows you to add or remove recipients from an encrypted file without re-encrypting the entire payload:

**Add a recipient:**
```bash
# Add a new recipient to an existing encrypted file
./ykcrypt rewrap --add "ykcrypt1:9d:1:..." --in secrets.ykc --out secrets-shared.ykc

# Add multiple recipients
./ykcrypt rewrap --add "ykcrypt1:..." --add "ykcrypt1:..." --in secrets.ykc

# Add recipients from a file (one per line)
./ykcrypt rewrap --add-file recipients.txt --in secrets.ykc
```

**Remove a recipient:**
```bash
# Remove a recipient by slot key (hex)
./ykcrypt rewrap --remove 9d --in secrets.ykc --out secrets.ykc
```

You must have access to one of the current recipients' keys (your YubiKey must be able to decrypt the file) to perform rewrap operations.

### Cipher Selection

You can choose between XChaCha20-Poly1305 (default) or AES-256-GCM:

```bash
# Encrypt using AES-256-GCM
./ykcrypt e --cipher aes secrets.txt

# Or with full command
./ykcrypt encrypt --cipher aes -in secrets.txt -out secrets.ykc
```

## Operational notes

- The `init` command defaults to the PIV management key value `default`. In real deployments you should change PIN/PUK/management key.
- Slot policies are set to require PIN + touch on use (`PINPolicyAlways`, `TouchPolicyAlways`).
- If you lose the YubiKey (and passphrase, if used), you lose access to the encrypted data.

## File format

ykcrypt supports two file formats:

- **YKCRYPT1**: Single recipient format (legacy, still fully supported)
- **YKCRYPT2**: Multiple recipient format with metadata support

The ciphertext begins with a fixed header and then a sequence of `(uint32 length, ciphertext bytes)` chunks terminated by length `0`.
The header includes the ephemeral public key(s), salts, nonce prefix, and wrapped file key(s). The full header is used as AAD for chunk AEAD.

For detailed format specification, see [FORMAT.md](FORMAT.md).

## Troubleshooting

Common errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| `security status not satisfied (6982)` | Touch timeout | Touch YubiKey within 15 seconds after PIN entry |
| `verification failed (63cx)` | Wrong PIN | Re-enter PIN (x = retries remaining) |
| `authentication blocked (6983)` | PIN blocked | Use PUK to unblock via YubiKey Manager |
| `data not found (6a82)` | Empty slot | Run `ykcrypt init` first |
| `no yubikey reader found` | No YubiKey | Plug in YubiKey; on Linux run `pcscd` |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
