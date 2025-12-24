/*
Copyright © 2025 Logicos Software

utils_test.go contains unit tests for the utility functions in utils.go.
These tests cover:
  - Recipient string parsing and generation
  - Cipher name parsing
  - Slot name parsing
  - Management key parsing
  - Curve ID mapping
  - Nonce prefix size calculation
  - Cipher name display
  - Length-prefixed byte operations
*/
package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// TestParseRecipient tests the ParseRecipient function with various inputs.
func TestParseRecipient(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		slotKey uint32
		curveID uint8
	}{
		{
			name:    "valid P256 recipient",
			input:   "ykcrypt1:9d:1:BGx0ZXN0cHVia2V5Ynl0ZXM",
			wantErr: false,
			slotKey: 0x9d,
			curveID: 1,
		},
		{
			name:    "valid P384 recipient",
			input:   "ykcrypt1:9a:2:BGFub3RoZXJ0ZXN0a2V5",
			wantErr: false,
			slotKey: 0x9a,
			curveID: 2,
		},
		{
			name:    "invalid prefix",
			input:   "ykcrypt2:9d:1:BGx0ZXN0cHVia2V5Ynl0ZXM",
			wantErr: true,
		},
		{
			name:    "missing parts",
			input:   "ykcrypt1:9d:1",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "ykcrypt1:9d:1:!!!invalid!!!",
			wantErr: true,
		},
		{
			name:    "invalid slot hex",
			input:   "ykcrypt1:zz:1:BGx0ZXN0cHVia2V5Ynl0ZXM",
			wantErr: true,
		},
		{
			name:    "invalid curve id",
			input:   "ykcrypt1:9d:abc:BGx0ZXN0cHVia2V5Ynl0ZXM",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseRecipient(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRecipient(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseRecipient(%q) unexpected error: %v", tt.input, err)
				return
			}
			if r.SlotKey != tt.slotKey {
				t.Errorf("SlotKey = %x, want %x", r.SlotKey, tt.slotKey)
			}
			if r.CurveID != tt.curveID {
				t.Errorf("CurveID = %d, want %d", r.CurveID, tt.curveID)
			}
		})
	}
}

// TestRecipientFromECDSAPublicKey tests generating recipient strings from ECDSA keys.
func TestRecipientFromECDSAPublicKey(t *testing.T) {
	// Generate a P-256 key for testing
	privP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	// Generate a P-384 key for testing
	privP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-384 key: %v", err)
	}

	tests := []struct {
		name      string
		slot      piv.Slot
		pub       *ecdsa.PublicKey
		wantErr   bool
		wantSlot  string
		wantCurve string
	}{
		{
			name:      "P-256 with slot 9d",
			slot:      piv.SlotKeyManagement,
			pub:       &privP256.PublicKey,
			wantErr:   false,
			wantSlot:  "9d",
			wantCurve: "1",
		},
		{
			name:      "P-384 with slot 9a",
			slot:      piv.SlotAuthentication,
			pub:       &privP384.PublicKey,
			wantErr:   false,
			wantSlot:  "9a",
			wantCurve: "2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipStr, err := RecipientFromECDSAPublicKey(tt.slot, tt.pub)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Parse back the recipient string to verify
			r, err := ParseRecipient(recipStr)
			if err != nil {
				t.Errorf("Failed to parse generated recipient: %v", err)
				return
			}

			if r.SlotKey != tt.slot.Key {
				t.Errorf("SlotKey = %x, want %x", r.SlotKey, tt.slot.Key)
			}
		})
	}
}

// TestRoundTripRecipient tests that recipient strings can be parsed back correctly.
func TestRoundTripRecipient(t *testing.T) {
	// Generate a key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	slot := piv.SlotKeyManagement

	// Create recipient string
	recipStr, err := RecipientFromECDSAPublicKey(slot, &priv.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create recipient string: %v", err)
	}

	// Parse it back
	r, err := ParseRecipient(recipStr)
	if err != nil {
		t.Fatalf("Failed to parse recipient: %v", err)
	}

	// Verify curve can be loaded
	curve, err := CurveFromID(r.CurveID)
	if err != nil {
		t.Fatalf("Failed to get curve: %v", err)
	}

	// Verify public key can be parsed
	_, err = curve.NewPublicKey(r.PubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}
}

// TestParseCipherName tests the ParseCipherName function.
func TestParseCipherName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantID  uint8
		wantErr bool
	}{
		{"chacha lowercase", "chacha", CipherChaCha20, false},
		{"chacha20", "chacha20", CipherChaCha20, false},
		{"xchacha20", "xchacha20", CipherChaCha20, false},
		{"xchacha20-poly1305", "xchacha20-poly1305", CipherChaCha20, false},
		{"CHACHA uppercase", "CHACHA", CipherChaCha20, false},
		{"aes lowercase", "aes", CipherAES256, false},
		{"aes256", "aes256", CipherAES256, false},
		{"aes-256", "aes-256", CipherAES256, false},
		{"aes-256-gcm", "aes-256-gcm", CipherAES256, false},
		{"aes256gcm", "aes256gcm", CipherAES256, false},
		{"AES uppercase", "AES", CipherAES256, false},
		{"invalid cipher", "blowfish", 0, true},
		{"empty string", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseCipherName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCipherName(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseCipherName(%q) unexpected error: %v", tt.input, err)
				return
			}
			if id != tt.wantID {
				t.Errorf("ParseCipherName(%q) = %d, want %d", tt.input, id, tt.wantID)
			}
		})
	}
}

// TestCipherName tests the CipherName function.
func TestCipherName(t *testing.T) {
	tests := []struct {
		id   uint8
		want string
	}{
		{CipherChaCha20, "XChaCha20-Poly1305"},
		{CipherAES256, "AES-256-GCM"},
		{99, "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := CipherName(tt.id)
			if got != tt.want {
				t.Errorf("CipherName(%d) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// TestNoncePrefixSize tests the NoncePrefixSize function.
func TestNoncePrefixSize(t *testing.T) {
	tests := []struct {
		cipherID uint8
		wantSize int
	}{
		{CipherChaCha20, 16},
		{CipherAES256, 4},
		{0, 16}, // Default (unknown) falls back to ChaCha
	}

	for _, tt := range tests {
		t.Run(CipherName(tt.cipherID), func(t *testing.T) {
			got := NoncePrefixSize(tt.cipherID)
			if got != tt.wantSize {
				t.Errorf("NoncePrefixSize(%d) = %d, want %d", tt.cipherID, got, tt.wantSize)
			}
		})
	}
}

// TestParseSlot tests the ParseSlot function.
func TestParseSlot(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey uint32
		wantErr bool
	}{
		{"9a", "9a", piv.SlotAuthentication.Key, false},
		{"9A uppercase", "9A", piv.SlotAuthentication.Key, false},
		{"auth", "auth", piv.SlotAuthentication.Key, false},
		{"authentication", "authentication", piv.SlotAuthentication.Key, false},
		{"9c", "9c", piv.SlotSignature.Key, false},
		{"sig", "sig", piv.SlotSignature.Key, false},
		{"signature", "signature", piv.SlotSignature.Key, false},
		{"9d", "9d", piv.SlotKeyManagement.Key, false},
		{"km", "km", piv.SlotKeyManagement.Key, false},
		{"keymgmt", "keymgmt", piv.SlotKeyManagement.Key, false},
		{"keymanagement", "keymanagement", piv.SlotKeyManagement.Key, false},
		{"9e", "9e", piv.SlotCardAuthentication.Key, false},
		{"cardauth", "cardauth", piv.SlotCardAuthentication.Key, false},
		{"cardauthentication", "cardauthentication", piv.SlotCardAuthentication.Key, false},
		{"invalid slot", "99", 0, true},
		{"empty string", "", 0, true},
		{"with whitespace", " 9d ", piv.SlotKeyManagement.Key, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, err := ParseSlot(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSlot(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSlot(%q) unexpected error: %v", tt.input, err)
				return
			}
			if slot.Key != tt.wantKey {
				t.Errorf("ParseSlot(%q).Key = %x, want %x", tt.input, slot.Key, tt.wantKey)
			}
		})
	}
}

// TestSlotFromKey tests the SlotFromKey function.
func TestSlotFromKey(t *testing.T) {
	tests := []struct {
		name    string
		key     uint32
		wantKey uint32
		wantErr bool
	}{
		{"authentication", piv.SlotAuthentication.Key, piv.SlotAuthentication.Key, false},
		{"signature", piv.SlotSignature.Key, piv.SlotSignature.Key, false},
		{"key management", piv.SlotKeyManagement.Key, piv.SlotKeyManagement.Key, false},
		{"card authentication", piv.SlotCardAuthentication.Key, piv.SlotCardAuthentication.Key, false},
		{"invalid key", 0xFF, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, err := SlotFromKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SlotFromKey(0x%x) expected error, got nil", tt.key)
				}
				return
			}
			if err != nil {
				t.Errorf("SlotFromKey(0x%x) unexpected error: %v", tt.key, err)
				return
			}
			if slot.Key != tt.wantKey {
				t.Errorf("SlotFromKey(0x%x).Key = %x, want %x", tt.key, slot.Key, tt.wantKey)
			}
		})
	}
}

// TestParseManagementKey tests the ParseManagementKey function.
func TestParseManagementKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"default lowercase", "default", 24, false},
		{"DEFAULT uppercase", "DEFAULT", 24, false},
		{"Default mixed case", "Default", 24, false},
		{"default with whitespace", " default ", 24, false},
		{"valid 24-byte hex", "010203040506070801020304050607080102030405060708", 24, false},
		{"valid hex with 0x prefix", "0x010203040506070801020304050607080102030405060708", 24, false},
		{"too short", "0102030405060708", 0, true},
		{"too long", "01020304050607080102030405060708010203040506070800", 0, true},
		{"invalid hex", "gggggggggggggggggggggggggggggggggggggggggggggggg", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseManagementKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseManagementKey(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseManagementKey(%q) unexpected error: %v", tt.input, err)
				return
			}
			if len(key) != tt.wantLen {
				t.Errorf("ParseManagementKey(%q) returned %d bytes, want %d", tt.input, len(key), tt.wantLen)
			}
		})
	}
}

// TestCurveFromID tests the CurveFromID function.
func TestCurveFromID(t *testing.T) {
	tests := []struct {
		name    string
		id      uint8
		wantErr bool
	}{
		{"P-256", curveP256, false},
		{"P-384", curveP384, false},
		{"invalid curve", 99, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curve, err := CurveFromID(tt.id)
			if tt.wantErr {
				if err == nil {
					t.Errorf("CurveFromID(%d) expected error, got nil", tt.id)
				}
				return
			}
			if err != nil {
				t.Errorf("CurveFromID(%d) unexpected error: %v", tt.id, err)
				return
			}
			if curve == nil {
				t.Error("CurveFromID returned nil curve")
			}
		})
	}
}

// TestWriteU16Bytes tests the WriteU16Bytes function.
func TestWriteU16Bytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantErr bool
	}{
		{"empty slice", []byte{}, 2, false},
		{"small slice", []byte{1, 2, 3}, 5, false},
		{"max size", make([]byte, 0xFFFF), 0xFFFF + 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteU16Bytes(&buf, tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if buf.Len() != tt.wantLen {
				t.Errorf("Buffer length = %d, want %d", buf.Len(), tt.wantLen)
			}
		})
	}
}

// TestWriteReadU16Bytes tests round-trip of WriteU16Bytes and ReadU16Bytes.
func TestWriteReadU16Bytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty slice", []byte{}},
		{"small slice", []byte{1, 2, 3, 4, 5}},
		{"larger slice", make([]byte, 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with random data for larger slices
			if len(tt.input) > 10 {
				rand.Read(tt.input)
			}

			// Write
			var buf bytes.Buffer
			err := WriteU16Bytes(&buf, tt.input)
			if err != nil {
				t.Fatalf("WriteU16Bytes failed: %v", err)
			}

			// Read
			result, err := ReadU16Bytes(&buf)
			if err != nil {
				t.Fatalf("ReadU16Bytes failed: %v", err)
			}

			// Compare
			if len(tt.input) == 0 {
				if result != nil {
					t.Errorf("Expected nil for empty input, got %v", result)
				}
			} else if !bytes.Equal(result, tt.input) {
				t.Errorf("Round-trip failed: got %v, want %v", result, tt.input)
			}
		})
	}
}

// TestMakeChunkNonce tests the MakeChunkNonce function.
func TestMakeChunkNonce(t *testing.T) {
	tests := []struct {
		name       string
		cipherID   uint8
		prefixSize int
		nonceSize  int
	}{
		{"ChaCha20", CipherChaCha20, 16, 24},
		{"AES-256-GCM", CipherAES256, 4, 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := make([]byte, tt.prefixSize)
			rand.Read(prefix)

			// Test chunk 0
			nonce0 := MakeChunkNonce(prefix, 0, tt.cipherID)
			if len(nonce0) != tt.nonceSize {
				t.Errorf("Nonce length = %d, want %d", len(nonce0), tt.nonceSize)
			}

			// Test chunk 1 - should be different
			nonce1 := MakeChunkNonce(prefix, 1, tt.cipherID)
			if bytes.Equal(nonce0, nonce1) {
				t.Error("Nonces for different chunks should be different")
			}

			// Same chunk index should produce same nonce
			nonce0Again := MakeChunkNonce(prefix, 0, tt.cipherID)
			if !bytes.Equal(nonce0, nonce0Again) {
				t.Error("Same chunk index should produce same nonce")
			}
		})
	}
}

// TestNewFileAEAD tests the NewFileAEAD function.
func TestNewFileAEAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tests := []struct {
		name      string
		cipherID  uint8
		nonceSize int
		wantErr   bool
	}{
		{"ChaCha20", CipherChaCha20, 24, false},
		{"AES-256-GCM", CipherAES256, 12, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := NewFileAEAD(key, tt.cipherID)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if aead.NonceSize() != tt.nonceSize {
				t.Errorf("NonceSize = %d, want %d", aead.NonceSize(), tt.nonceSize)
			}
		})
	}
}

// TestNewFileAEADEncryptDecrypt tests encryption/decryption with NewFileAEAD.
func TestNewFileAEADEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("Hello, World! This is a test message for encryption.")
	additionalData := []byte("additional authenticated data")

	ciphers := []uint8{CipherChaCha20, CipherAES256}

	for _, cipherID := range ciphers {
		t.Run(CipherName(cipherID), func(t *testing.T) {
			aead, err := NewFileAEAD(key, cipherID)
			if err != nil {
				t.Fatalf("NewFileAEAD failed: %v", err)
			}

			// Create nonce
			nonce := make([]byte, aead.NonceSize())
			rand.Read(nonce)

			// Encrypt
			ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

			// Decrypt
			decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("Decrypted text doesn't match plaintext")
			}

			// Verify tampering is detected
			ciphertext[0] ^= 0xFF
			_, err = aead.Open(nil, nonce, ciphertext, additionalData)
			if err == nil {
				t.Error("Tampered ciphertext should fail authentication")
			}
		})
	}
}
