/*
Package cmd provides utility functions, types, and constants for ykcrypt.

This file contains:
  - Version information variables (set via ldflags)
  - File format constants (magic bytes, curve IDs, cipher IDs)
  - Header struct and serialization/deserialization
  - Recipient string parsing and generation
  - Cryptographic utility functions (key derivation, AEAD creation)
  - YubiKey interaction helpers
  - Error handling utilities
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

// Version information variables.
// These are set via ldflags during the build process:
//
//	go build -ldflags "-X ykcrypt/cmd.Version=1.0.0 -X ykcrypt/cmd.GitCommit=abc123 ..."
var (
	Version   = "dev"     // Semantic version (e.g., "1.0.0")
	BuildTime = "unknown" // Build timestamp
	GitCommit = "unknown" // Git commit hash
	GoVersion = "unknown" // Go compiler version
)

// magic is the file format identifier.
// All ykcrypt encrypted files begin with this 8-byte magic string.
const (
	magic = "YKCRYPT1"
)

// Elliptic curve identifiers for the file format.
// These are stored in the header to identify which curve was used.
const (
	curveP256 uint8 = 1 // NIST P-256 (secp256r1)
	curveP384 uint8 = 2 // NIST P-384 (secp384r1)
)

// Header flags for optional features.
const (
	flagHasPassphrase uint8 = 1 << 0 // Indicates passphrase was used as second factor
)

// Cipher identifiers for symmetric encryption.
// These are stored in the header to identify which cipher was used.
const (
	CipherChaCha20 uint8 = 1 // XChaCha20-Poly1305 (default, 256-bit key, 192-bit nonce)
	CipherAES256   uint8 = 2 // AES-256-GCM (256-bit key, 96-bit nonce)
)

// Header represents the encrypted file header.
// It contains all metadata needed to decrypt the file, including:
//   - Version and algorithm identifiers
//   - Ephemeral public key for ECDH
//   - Salt values for key derivation
//   - The wrapped (encrypted) file key
//
// The header is serialized at the beginning of every encrypted file
// and is used as additional authenticated data (AAD) for chunk encryption.
type Header struct {
	Version     uint8  // File format version (currently 1)
	CurveID     uint8  // Elliptic curve identifier (curveP256 or curveP384)
	CipherID    uint8  // Cipher identifier (CipherChaCha20 or CipherAES256)
	SlotKey     uint32 // PIV slot key identifier (e.g., 0x9d for Key Management)
	Flags       uint8  // Feature flags (e.g., flagHasPassphrase)
	EphPub      []byte // Ephemeral public key bytes (SEC1 uncompressed format)
	Salt        []byte // HKDF salt for wrap key derivation (16 bytes)
	PassSalt    []byte // Argon2id salt for passphrase (16 bytes, empty if no passphrase)
	NoncePrefix []byte // Nonce prefix for chunk encryption (16 bytes for ChaCha, 4 for AES)
	ChunkSize   uint32 // Plaintext chunk size in bytes
	WrapNonce   []byte // Nonce for key wrapping AEAD (12 bytes)
	WrappedKey  []byte // Encrypted file key (32 bytes + 16 bytes auth tag)
}

// MarshalPrefixAAD serializes the header up to (but not including) the wrapped key.
// This prefix is used as Additional Authenticated Data (AAD) for the key wrapping
// operation, binding the wrapped key to the header contents.
//
// Returns the serialized prefix bytes or an error if serialization fails.
func (h Header) MarshalPrefixAAD() ([]byte, error) {
	var b bytes.Buffer
	if _, err := b.Write([]byte(magic)); err != nil {
		return nil, err
	}
	b.WriteByte(h.Version)
	b.WriteByte(h.CurveID)
	b.WriteByte(h.CipherID)
	if err := binary.Write(&b, binary.LittleEndian, h.SlotKey); err != nil {
		return nil, err
	}
	b.WriteByte(h.Flags)

	if err := WriteU16Bytes(&b, h.EphPub); err != nil {
		return nil, err
	}
	if err := WriteU16Bytes(&b, h.Salt); err != nil {
		return nil, err
	}
	if err := WriteU16Bytes(&b, h.PassSalt); err != nil {
		return nil, err
	}
	// NoncePrefix: 16 bytes for ChaCha, can vary for AES
	if err := WriteU16Bytes(&b, h.NoncePrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, h.ChunkSize); err != nil {
		return nil, err
	}
	if len(h.WrapNonce) != 12 {
		return nil, fmt.Errorf("wrapNonce must be 12 bytes, got %d", len(h.WrapNonce))
	}
	if _, err := b.Write(h.WrapNonce); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// MarshalFull serializes the complete header including the wrapped key.
// This is written to the beginning of the encrypted file and is also
// used as AAD for chunk encryption.
//
// Returns the complete serialized header or an error if serialization fails.
func (h Header) MarshalFull() ([]byte, error) {
	prefix, err := h.MarshalPrefixAAD()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Write(prefix)
	if err := WriteU16Bytes(&b, h.WrappedKey); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ParseHeader reads and parses an encrypted file header from a buffered reader.
// It validates the magic bytes and extracts all header fields.
//
// Returns:
//   - h: The parsed Header struct
//   - fullHeader: Complete header bytes (for use as AAD in chunk decryption)
//   - wrapAAD: Header prefix bytes (for use as AAD in key unwrapping)
//   - err: Error if parsing fails (e.g., invalid magic, unexpected EOF)
//
// If the magic bytes don't match, returns a user-friendly error message
// suggesting the file may already be decrypted.
func ParseHeader(br *bufio.Reader) (Header, []byte, []byte, error) {
	var h Header
	var full bytes.Buffer
	var prefix bytes.Buffer

	m := make([]byte, len(magic))
	if _, err := io.ReadFull(br, m); err != nil {
		return h, nil, nil, err
	}
	if string(m) != magic {
		return h, nil, nil, fmt.Errorf("this doesn't look like an encrypted file (expected magic %q, got %q). Did you perhaps try to decrypt something that's already decrypted? The YubiKey is confused and frankly, so am I", magic, string(m))
	}
	full.Write(m)
	prefix.Write(m)

	v, err := br.ReadByte()
	if err != nil {
		return h, nil, nil, err
	}
	h.Version = v
	full.WriteByte(v)
	prefix.WriteByte(v)

	cid, err := br.ReadByte()
	if err != nil {
		return h, nil, nil, err
	}
	h.CurveID = cid
	full.WriteByte(cid)
	prefix.WriteByte(cid)

	// CipherID (new in v1 with cipher support)
	cipherID, err := br.ReadByte()
	if err != nil {
		return h, nil, nil, err
	}
	h.CipherID = cipherID
	full.WriteByte(cipherID)
	prefix.WriteByte(cipherID)

	if err := binary.Read(br, binary.LittleEndian, &h.SlotKey); err != nil {
		return h, nil, nil, err
	}
	_ = binary.Write(&full, binary.LittleEndian, h.SlotKey)
	_ = binary.Write(&prefix, binary.LittleEndian, h.SlotKey)

	flags, err := br.ReadByte()
	if err != nil {
		return h, nil, nil, err
	}
	h.Flags = flags
	full.WriteByte(flags)
	prefix.WriteByte(flags)

	readAndAppend := func(dst *[]byte) error {
		b, err := ReadU16Bytes(br)
		if err != nil {
			return err
		}
		*dst = b

		var tmp bytes.Buffer
		if err := WriteU16Bytes(&tmp, b); err != nil {
			return err
		}
		full.Write(tmp.Bytes())
		prefix.Write(tmp.Bytes())
		return nil
	}

	// EphPub, Salt, PassSalt, NoncePrefix
	if err := readAndAppend(&h.EphPub); err != nil {
		return h, nil, nil, err
	}
	if err := readAndAppend(&h.Salt); err != nil {
		return h, nil, nil, err
	}
	if err := readAndAppend(&h.PassSalt); err != nil {
		return h, nil, nil, err
	}
	if err := readAndAppend(&h.NoncePrefix); err != nil {
		return h, nil, nil, err
	}

	if err := binary.Read(br, binary.LittleEndian, &h.ChunkSize); err != nil {
		return h, nil, nil, err
	}
	_ = binary.Write(&full, binary.LittleEndian, h.ChunkSize)
	_ = binary.Write(&prefix, binary.LittleEndian, h.ChunkSize)

	h.WrapNonce = make([]byte, 12)
	if _, err := io.ReadFull(br, h.WrapNonce); err != nil {
		return h, nil, nil, err
	}
	full.Write(h.WrapNonce)
	prefix.Write(h.WrapNonce)

	// prefix AAD snapshot (everything up to and including WrapNonce)
	wrapAAD := prefix.Bytes()

	// WrappedKey (only goes into full header)
	wk, err := ReadU16Bytes(br)
	if err != nil {
		return h, nil, nil, err
	}
	h.WrappedKey = wk
	if err := WriteU16Bytes(&full, wk); err != nil {
		return h, nil, nil, err
	}

	return h, full.Bytes(), wrapAAD, nil
}

// WriteU16Bytes writes a length-prefixed byte slice to a writer.
// The length is encoded as a 2-byte little-endian unsigned integer,
// followed by the actual bytes.
//
// Maximum supported length is 65535 bytes (0xFFFF).
// Returns an error if the slice is too large or if writing fails.
func WriteU16Bytes(w io.Writer, b []byte) error {
	if len(b) > 0xFFFF {
		return fmt.Errorf("blob too large: %d", len(b))
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// ReadU16Bytes reads a length-prefixed byte slice from a reader.
// It expects a 2-byte little-endian length followed by that many bytes.
//
// Returns nil slice (not error) if length is zero.
// Returns error on read failure or unexpected EOF.
func ReadU16Bytes(r io.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Recipient represents the public key information needed for encryption.
// It encapsulates the slot identifier, curve type, and public key bytes.
// Recipients can be serialized to/from recipient strings for easy sharing.
type Recipient struct {
	SlotKey     uint32 // PIV slot key identifier (e.g., 0x9d)
	CurveID     uint8  // Elliptic curve identifier
	PubKeyBytes []byte // SEC1 uncompressed public key bytes
}

// RecipientFromCert extracts a Recipient from an X.509 certificate.
// The certificate must contain an ECDSA public key on a supported curve.
//
// This is used to get the recipient from a YubiKey slot's certificate.
func RecipientFromCert(slot piv.Slot, cert *x509.Certificate) (Recipient, error) {
	ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return Recipient{}, fmt.Errorf("cert public key type %T, expected *ecdsa.PublicKey", cert.PublicKey)
	}
	recipStr, err := RecipientFromECDSAPublicKey(slot, ecdsaPub)
	if err != nil {
		return Recipient{}, err
	}
	return ParseRecipient(recipStr)
}

// RecipientFromECDSAPublicKey creates a recipient string from an ECDSA public key.
// The recipient string format is: ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>
//
// The public key is encoded in SEC1 uncompressed point format and base64-encoded.
// Returns error if the curve is not supported (only P-256 and P-384).
func RecipientFromECDSAPublicKey(slot piv.Slot, pub *ecdsa.PublicKey) (string, error) {
	var curveID uint8
	switch pub.Curve {
	case elliptic.P256():
		curveID = curveP256
	case elliptic.P384():
		curveID = curveP384
	default:
		return "", fmt.Errorf("unsupported curve")
	}
	// SEC1 uncompressed point encoding: 0x04 || X || Y
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	b64 := base64.RawStdEncoding.EncodeToString(point)
	return fmt.Sprintf("ykcrypt1:%02x:%d:%s", slot.Key, curveID, b64), nil
}

// ParseRecipient parses a recipient string into a Recipient struct.
// Expected format: ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>
//
// Example: ykcrypt1:9d:1:BGx...base64...
//
// Returns error if format is invalid or base64 decoding fails.
func ParseRecipient(s string) (Recipient, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 || parts[0] != "ykcrypt1" {
		return Recipient{}, fmt.Errorf("invalid recipient format (expected ykcrypt1:<slotHex>:<curveId>:<b64pub>)")
	}
	// Parse slot key as hexadecimal
	var slotKey uint32
	_, err := fmt.Sscanf(parts[1], "%x", &slotKey)
	if err != nil {
		return Recipient{}, fmt.Errorf("parse slot hex: %w", err)
	}
	// Parse curve ID as decimal
	var curveID int
	if _, err := fmt.Sscanf(parts[2], "%d", &curveID); err != nil {
		return Recipient{}, fmt.Errorf("parse curve id: %w", err)
	}
	// Decode base64 public key
	pubBytes, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return Recipient{}, fmt.Errorf("decode pubkey: %w", err)
	}
	return Recipient{
		SlotKey:     slotKey,
		CurveID:     uint8(curveID),
		PubKeyBytes: pubBytes,
	}, nil
}

// CurveFromID returns the ECDH curve corresponding to a curve ID.
// Supports P-256 (curveP256=1) and P-384 (curveP384=2).
//
// Returns error for unsupported curve IDs.
func CurveFromID(id uint8) (ecdh.Curve, error) {
	switch id {
	case curveP256:
		return ecdh.P256(), nil
	case curveP384:
		return ecdh.P384(), nil
	default:
		return nil, fmt.Errorf("unsupported curve id %d", id)
	}
}

// DeriveWrapKey derives a 256-bit wrap key from the ECDH shared secret.
// The derivation uses HKDF-SHA256 with the provided salt and a fixed info string.
//
// If a passphrase is provided, the key is further processed:
//  1. Argon2id is used to derive a key from the passphrase
//  2. HMAC-SHA256 combines the HKDF output with the passphrase-derived key
//
// This provides defense in depth - an attacker needs both the YubiKey
// (for ECDH) and the passphrase to derive the correct wrap key.
//
// Parameters:
//   - sharedSecret: ECDH shared secret from key agreement
//   - salt: Random salt for HKDF (from header)
//   - passSalt: Random salt for Argon2id (from header, empty if no passphrase)
//   - passphrase: User passphrase (empty if not using second factor)
//
// Returns the 32-byte wrap key or error.
func DeriveWrapKey(sharedSecret, salt, passSalt []byte, passphrase string) ([]byte, error) {
	// First, derive key from shared secret using HKDF
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte("ykcrypt wrap v1"))
	wk := make([]byte, 32)
	if _, err := io.ReadFull(h, wk); err != nil {
		return nil, err
	}

	// If no passphrase, we're done
	if passphrase == "" {
		return wk, nil
	}

	// Validate passphrase salt is present
	if len(passSalt) == 0 {
		return nil, errors.New("ciphertext requires passphrase but passSalt is empty")
	}

	// Derive passphrase key using Argon2id
	// Parameters: time=3, memory=64MB, parallelism=4, output=32 bytes
	pk := argon2.IDKey([]byte(passphrase), passSalt, 3, 64*1024, 4, 32)

	// Combine HKDF output with passphrase key using HMAC
	m := hmac.New(sha256.New, pk)
	_, _ = m.Write(wk)
	return m.Sum(nil), nil
}

// MakeChunkNonce creates a unique nonce for encrypting a specific chunk.
// The nonce is constructed from a random prefix and the chunk index.
//
// For XChaCha20-Poly1305 (24-byte nonce):
//   - Bytes 0-15: Random prefix
//   - Bytes 16-23: Big-endian chunk index
//
// For AES-256-GCM (12-byte nonce):
//   - Bytes 0-3: Random prefix (first 4 bytes)
//   - Bytes 4-11: Big-endian chunk index
//
// This construction ensures each chunk has a unique nonce while being
// deterministic for the same prefix and index (needed for random access).
func MakeChunkNonce(prefix []byte, idx uint64, cipherID uint8) []byte {
	switch cipherID {
	case CipherAES256:
		// AES-GCM uses 12-byte nonces
		nonce := make([]byte, 12)
		copy(nonce[:4], prefix[:4])
		binary.BigEndian.PutUint64(nonce[4:], idx)
		return nonce
	default:
		// XChaCha20-Poly1305 uses 24-byte nonces
		nonce := make([]byte, 24)
		copy(nonce[:16], prefix)
		binary.BigEndian.PutUint64(nonce[16:], idx)
		return nonce
	}
}

// NewFileAEAD creates an AEAD cipher for file content encryption.
// The cipher is selected based on the cipher ID from the header.
//
// Supported ciphers:
//   - CipherChaCha20 (1): XChaCha20-Poly1305 with 24-byte nonces
//   - CipherAES256 (2): AES-256-GCM with 12-byte nonces
//
// Both use 256-bit keys and provide authenticated encryption.
func NewFileAEAD(fileKey []byte, cipherID uint8) (cipher.AEAD, error) {
	switch cipherID {
	case CipherAES256:
		block, err := aes.NewCipher(fileKey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		// XChaCha20-Poly1305 (default)
		return chacha20poly1305.NewX(fileKey)
	}
}

// NoncePrefixSize returns the required random nonce prefix size for a cipher.
//
// The prefix is combined with a chunk counter to create unique nonces:
//   - XChaCha20-Poly1305: 16 bytes prefix + 8 bytes counter = 24 bytes total
//   - AES-256-GCM: 4 bytes prefix + 8 bytes counter = 12 bytes total
func NoncePrefixSize(cipherID uint8) int {
	switch cipherID {
	case CipherAES256:
		return 4 // 4 bytes prefix + 8 bytes counter for 12-byte GCM nonce
	default:
		return 16 // 16 bytes prefix + 8 bytes counter for 24-byte XChaCha nonce
	}
}

// CipherName returns a human-readable name for a cipher ID.
// Used for display purposes in logs and error messages.
func CipherName(cipherID uint8) string {
	switch cipherID {
	case CipherAES256:
		return "AES-256-GCM"
	case CipherChaCha20:
		return "XChaCha20-Poly1305"
	default:
		return fmt.Sprintf("unknown(%d)", cipherID)
	}
}

// ParseCipherName converts a user-provided cipher name to a cipher ID.
// Accepts various common aliases for each cipher.
//
// ChaCha20 aliases: chacha, chacha20, xchacha20, xchacha20-poly1305
// AES-256 aliases: aes, aes256, aes-256, aes-256-gcm, aes256gcm
//
// Returns error for unrecognized cipher names.
func ParseCipherName(name string) (uint8, error) {
	switch strings.ToLower(name) {
	case "chacha", "chacha20", "xchacha20", "xchacha20-poly1305":
		return CipherChaCha20, nil
	case "aes", "aes256", "aes-256", "aes-256-gcm", "aes256gcm":
		return CipherAES256, nil
	default:
		return 0, fmt.Errorf("unknown cipher %q (use 'chacha' or 'aes')", name)
	}
}

// MustRand generates n cryptographically secure random bytes.
// Panics (via ExitWithError) if the random source fails.
//
// This is used for generating salts, nonces, and file keys.
func MustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		ExitWithError(err)
	}
	return b
}

// PromptHidden prompts the user for input without echoing to the terminal.
// This is used for PIN and passphrase entry.
//
// If stdin is a terminal, uses terminal.ReadPassword for secure input.
// Falls back to normal reading if not a terminal (e.g., piped input).
//
// Returns the trimmed input string or error.
func PromptHidden(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		// Secure terminal input (no echo)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) // Newline after hidden input
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	// Fallback for non-terminal input
	var s string
	_, err := fmt.Fscanln(os.Stdin, &s)
	return strings.TrimSpace(s), err
}

// MustPromptPassphrase prompts for a passphrase and exits on error or empty input.
// Used when a passphrase is required (e.g., encryption with -p flag).
func MustPromptPassphrase(prompt string) string {
	p, err := PromptHidden(prompt)
	if err != nil {
		ExitWithError(err)
	}
	if p == "" {
		ExitWithErrorMsg("empty passphrase not allowed")
	}
	return p
}

// OpenYubiKey opens a connection to a YubiKey.
//
// If reader is non-empty, opens that specific reader.
// Otherwise, scans for available smart card readers and opens the first
// one with "yubikey" in the name (case-insensitive).
//
// Returns:
//   - yk: The opened YubiKey handle
//   - closeFn: A function to close the connection (call with defer)
//   - err: Error if no YubiKey found or connection failed
func OpenYubiKey(reader string) (*piv.YubiKey, func(), error) {
	if reader != "" {
		// Open specific reader
		yk, err := piv.Open(reader)
		if err != nil {
			return nil, nil, err
		}
		return yk, func() { _ = yk.Close() }, nil
	}

	// Scan for YubiKey readers
	cards, err := piv.Cards()
	if err != nil {
		return nil, nil, err
	}
	for _, c := range cards {
		if strings.Contains(strings.ToLower(c), "yubikey") {
			yk, err := piv.Open(c)
			if err != nil {
				continue // Try next reader
			}
			return yk, func() { _ = yk.Close() }, nil
		}
	}
	return nil, nil, fmt.Errorf("no yubikey reader found")
}

// ParseSlot converts a slot name/ID string to a piv.Slot.
// Accepts both hex IDs (9a, 9c, 9d, 9e) and friendly names.
//
// Supported slots:
//   - 9a / auth / authentication: PIV Authentication
//   - 9c / sig / signature: Digital Signature
//   - 9d / km / keymgmt / keymanagement: Key Management (default for ykcrypt)
//   - 9e / cardauth / cardauthentication: Card Authentication
//
// Returns error for unsupported slot names.
func ParseSlot(s string) (piv.Slot, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "9a", "auth", "authentication":
		return piv.SlotAuthentication, nil
	case "9c", "sig", "signature":
		return piv.SlotSignature, nil
	case "9d", "km", "keymgmt", "keymanagement":
		return piv.SlotKeyManagement, nil
	case "9e", "cardauth", "cardauthentication":
		return piv.SlotCardAuthentication, nil
	default:
		return piv.Slot{}, fmt.Errorf("unsupported slot %q (use 9a, 9c, 9d, or 9e)", s)
	}
}

// SlotFromKey converts a PIV slot key value to a piv.Slot.
// The slot key is the numeric identifier stored in the file header.
//
// This is the inverse of piv.Slot.Key - it maps key values back to slots.
// Returns error for unsupported slot keys.
func SlotFromKey(k uint32) (piv.Slot, error) {
	switch k {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, nil
	case piv.SlotSignature.Key:
		return piv.SlotSignature, nil
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, nil
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, nil
	default:
		return piv.Slot{}, fmt.Errorf("unsupported slot key 0x%x (only 9a/9c/9d/9e supported)", k)
	}
}

// MakePINPromptAuth creates a piv.KeyAuth with a PIN prompt callback.
// The callback is invoked when a PIV operation requires PIN authentication.
//
// This allows lazy PIN prompting - the PIN is only requested when needed,
// and can be cached by the callback for subsequent operations.
func MakePINPromptAuth(prompt func() (string, error)) piv.KeyAuth {
	return piv.KeyAuth{
		PINPrompt: prompt,
	}
}

// ParseManagementKey parses a management key from hex string or "default".
// The management key is required for key generation and certificate operations.
//
// If the input is "default" (case-insensitive), returns piv.DefaultManagementKey.
// Otherwise, expects 48 hex characters (24 bytes) with optional "0x" prefix.
//
// Returns error if the hex is invalid or wrong length.
func ParseManagementKey(s string) ([]byte, error) {
	if strings.EqualFold(strings.TrimSpace(s), "default") {
		return piv.DefaultManagementKey, nil
	}
	// Decode hex, stripping optional 0x prefix
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode mgmt key hex: %w", err)
	}
	if len(b) != 24 {
		return nil, fmt.Errorf("management key must be 24 bytes (48 hex chars), got %d bytes", len(b))
	}
	return b, nil
}

// MakeContainerCert creates a self-signed certificate containing an EC public key.
// This is used to store the YubiKey's public key in the slot certificate,
// enabling later retrieval without needing attestation.
//
// The certificate is signed by an ephemeral software CA key (not the YubiKey)
// because the YubiKey's ECDH key cannot perform signing operations.
//
// Parameters:
//   - pub: The ECDSA public key to embed in the certificate
//   - cn: Common Name for the certificate subject
//
// Returns:
//   - der: DER-encoded certificate bytes
//   - cert: Parsed X.509 certificate
//   - err: Error if certificate creation fails
//
// The certificate is valid for 20 years from creation.
func MakeContainerCert(pub *ecdsa.PublicKey, cn string) ([]byte, *x509.Certificate, error) {
	// Create an ephemeral software CA key matching the public key's curve
	var caPriv *ecdsa.PrivateKey
	var err error
	switch pub.Curve {
	case elliptic.P256():
		caPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case elliptic.P384():
		caPriv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unsupported curve")
	}
	if err != nil {
		return nil, nil, err
	}

	// Generate random serial number
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()

	// Create leaf certificate template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute), // Allow for clock skew
		NotAfter:     now.AddDate(20, 0, 0),     // Valid for 20 years
		KeyUsage:     x509.KeyUsageKeyAgreement, // For ECDH
	}

	// Create issuer certificate template (ephemeral CA)
	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ykcrypt container cert issuer"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Create the certificate (signed by ephemeral CA)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, caPriv)
	if err != nil {
		return nil, nil, err
	}

	// Parse to verify and return
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, cert, nil
}

// ExitWithError prints an error message to stderr and exits with code 1.
// Does nothing if err is nil.
//
// This is the standard way to handle fatal errors in ykcrypt commands.
func ExitWithError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// ExitWithErrorMsg formats and prints an error message to stderr, then exits with code 1.
// Uses fmt.Sprintf-style formatting.
//
// This is the standard way to handle fatal errors with custom messages.
func ExitWithErrorMsg(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
