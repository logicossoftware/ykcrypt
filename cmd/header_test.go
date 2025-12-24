/*
Copyright © 2025 Logicos Software

header_test.go contains unit tests for the Header struct and its
serialization/deserialization methods.

These tests cover:
  - Header marshaling (MarshalPrefixAAD, MarshalFull)
  - Header parsing (ParseHeader)
  - Round-trip serialization
  - Error handling for malformed headers
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"testing"
)

// createTestHeader creates a valid Header for testing purposes.
func createTestHeader(cipherID uint8) Header {
	// Generate random ephemeral public key (65 bytes for P-256 uncompressed)
	ephPub := make([]byte, 65)
	rand.Read(ephPub)
	ephPub[0] = 0x04 // Uncompressed point marker

	// Generate random cryptographic materials
	salt := make([]byte, 16)
	rand.Read(salt)

	passSalt := make([]byte, 16)
	rand.Read(passSalt)

	noncePrefix := make([]byte, NoncePrefixSize(cipherID))
	rand.Read(noncePrefix)

	wrapNonce := make([]byte, 12)
	rand.Read(wrapNonce)

	// Wrapped key is 32 bytes key + 16 bytes auth tag = 48 bytes
	wrappedKey := make([]byte, 48)
	rand.Read(wrappedKey)

	return Header{
		Version:     1,
		CurveID:     curveP256,
		CipherID:    cipherID,
		SlotKey:     0x9d,
		Flags:       flagHasPassphrase,
		EphPub:      ephPub,
		Salt:        salt,
		PassSalt:    passSalt,
		NoncePrefix: noncePrefix,
		ChunkSize:   1 << 20, // 1 MiB
		WrapNonce:   wrapNonce,
		WrappedKey:  wrappedKey,
	}
}

// TestHeaderMarshalPrefixAAD tests the MarshalPrefixAAD method.
func TestHeaderMarshalPrefixAAD(t *testing.T) {
	tests := []struct {
		name     string
		cipherID uint8
	}{
		{"ChaCha20", CipherChaCha20},
		{"AES-256-GCM", CipherAES256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := createTestHeader(tt.cipherID)

			prefix, err := h.MarshalPrefixAAD()
			if err != nil {
				t.Fatalf("MarshalPrefixAAD failed: %v", err)
			}

			// Verify magic bytes
			if string(prefix[:8]) != magic {
				t.Errorf("Magic bytes = %q, want %q", string(prefix[:8]), magic)
			}

			// Verify version
			if prefix[8] != 1 {
				t.Errorf("Version = %d, want 1", prefix[8])
			}

			// Verify curve ID
			if prefix[9] != curveP256 {
				t.Errorf("CurveID = %d, want %d", prefix[9], curveP256)
			}

			// Verify cipher ID
			if prefix[10] != tt.cipherID {
				t.Errorf("CipherID = %d, want %d", prefix[10], tt.cipherID)
			}
		})
	}
}

// TestHeaderMarshalFull tests the MarshalFull method.
func TestHeaderMarshalFull(t *testing.T) {
	h := createTestHeader(CipherChaCha20)

	full, err := h.MarshalFull()
	if err != nil {
		t.Fatalf("MarshalFull failed: %v", err)
	}

	prefix, err := h.MarshalPrefixAAD()
	if err != nil {
		t.Fatalf("MarshalPrefixAAD failed: %v", err)
	}

	// Full header should be longer than prefix (contains wrapped key)
	if len(full) <= len(prefix) {
		t.Errorf("Full header (%d bytes) should be longer than prefix (%d bytes)",
			len(full), len(prefix))
	}

	// Full header should start with prefix
	if !bytes.HasPrefix(full, prefix) {
		t.Error("Full header should start with prefix")
	}
}

// TestHeaderRoundTrip tests serialization and parsing round-trip.
func TestHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		cipherID uint8
		flags    uint8
	}{
		{"ChaCha20 with passphrase", CipherChaCha20, flagHasPassphrase},
		{"ChaCha20 without passphrase", CipherChaCha20, 0},
		{"AES-256-GCM with passphrase", CipherAES256, flagHasPassphrase},
		{"AES-256-GCM without passphrase", CipherAES256, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create header
			h := createTestHeader(tt.cipherID)
			h.Flags = tt.flags
			if tt.flags == 0 {
				h.PassSalt = nil // No passphrase salt when no passphrase
			}

			// Serialize
			full, err := h.MarshalFull()
			if err != nil {
				t.Fatalf("MarshalFull failed: %v", err)
			}

			// Parse
			br := bufio.NewReader(bytes.NewReader(full))
			parsed, fullHeader, wrapAAD, err := ParseHeader(br)
			if err != nil {
				t.Fatalf("ParseHeader failed: %v", err)
			}

			// Verify all fields match
			if parsed.Version != h.Version {
				t.Errorf("Version = %d, want %d", parsed.Version, h.Version)
			}
			if parsed.CurveID != h.CurveID {
				t.Errorf("CurveID = %d, want %d", parsed.CurveID, h.CurveID)
			}
			if parsed.CipherID != h.CipherID {
				t.Errorf("CipherID = %d, want %d", parsed.CipherID, h.CipherID)
			}
			if parsed.SlotKey != h.SlotKey {
				t.Errorf("SlotKey = %x, want %x", parsed.SlotKey, h.SlotKey)
			}
			if parsed.Flags != h.Flags {
				t.Errorf("Flags = %d, want %d", parsed.Flags, h.Flags)
			}
			if !bytes.Equal(parsed.EphPub, h.EphPub) {
				t.Error("EphPub mismatch")
			}
			if !bytes.Equal(parsed.Salt, h.Salt) {
				t.Error("Salt mismatch")
			}
			if !bytes.Equal(parsed.PassSalt, h.PassSalt) {
				t.Error("PassSalt mismatch")
			}
			if !bytes.Equal(parsed.NoncePrefix, h.NoncePrefix) {
				t.Error("NoncePrefix mismatch")
			}
			if parsed.ChunkSize != h.ChunkSize {
				t.Errorf("ChunkSize = %d, want %d", parsed.ChunkSize, h.ChunkSize)
			}
			if !bytes.Equal(parsed.WrapNonce, h.WrapNonce) {
				t.Error("WrapNonce mismatch")
			}
			if !bytes.Equal(parsed.WrappedKey, h.WrappedKey) {
				t.Error("WrappedKey mismatch")
			}

			// Verify fullHeader matches original
			if !bytes.Equal(fullHeader, full) {
				t.Error("fullHeader doesn't match original serialization")
			}

			// Verify wrapAAD is a prefix of fullHeader
			if !bytes.HasPrefix(fullHeader, wrapAAD) {
				t.Error("wrapAAD should be a prefix of fullHeader")
			}
		})
	}
}

// TestParseHeaderInvalidMagic tests parsing with invalid magic bytes.
func TestParseHeaderInvalidMagic(t *testing.T) {
	// Create a buffer with wrong magic
	data := []byte("WRONGMAG" + "rest of header data...")

	br := bufio.NewReader(bytes.NewReader(data))
	_, _, _, err := ParseHeader(br)

	if err == nil {
		t.Error("Expected error for invalid magic, got nil")
	}

	// Error message should mention the issue
	if !bytes.Contains([]byte(err.Error()), []byte("encrypted file")) {
		t.Errorf("Error should mention encrypted file issue: %v", err)
	}
}

// TestParseHeaderTruncated tests parsing with truncated data.
func TestParseHeaderTruncated(t *testing.T) {
	// Create a valid header
	h := createTestHeader(CipherChaCha20)
	full, err := h.MarshalFull()
	if err != nil {
		t.Fatalf("MarshalFull failed: %v", err)
	}

	// Test with various truncation points
	truncationPoints := []int{0, 7, 8, 15, 30, len(full) / 2}

	for _, truncAt := range truncationPoints {
		if truncAt >= len(full) {
			continue
		}
		t.Run("truncated at byte "+string(rune('0'+truncAt)), func(t *testing.T) {
			truncated := full[:truncAt]
			br := bufio.NewReader(bytes.NewReader(truncated))
			_, _, _, err := ParseHeader(br)
			if err == nil {
				t.Error("Expected error for truncated header, got nil")
			}
		})
	}
}

// TestHeaderWrapNonceLength tests that WrapNonce must be exactly 12 bytes.
func TestHeaderWrapNonceLength(t *testing.T) {
	tests := []struct {
		name     string
		nonceLen int
		wantErr  bool
	}{
		{"10 bytes", 10, true},
		{"11 bytes", 11, true},
		{"12 bytes", 12, false},
		{"13 bytes", 13, true},
		{"16 bytes", 16, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := createTestHeader(CipherChaCha20)
			h.WrapNonce = make([]byte, tt.nonceLen)
			rand.Read(h.WrapNonce)

			_, err := h.MarshalPrefixAAD()
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error for wrong WrapNonce length, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestHeaderP384Curve tests header with P-384 curve.
func TestHeaderP384Curve(t *testing.T) {
	h := createTestHeader(CipherChaCha20)
	h.CurveID = curveP384
	// P-384 uncompressed point is 97 bytes
	h.EphPub = make([]byte, 97)
	rand.Read(h.EphPub)
	h.EphPub[0] = 0x04

	// Serialize
	full, err := h.MarshalFull()
	if err != nil {
		t.Fatalf("MarshalFull failed: %v", err)
	}

	// Parse
	br := bufio.NewReader(bytes.NewReader(full))
	parsed, _, _, err := ParseHeader(br)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}

	if parsed.CurveID != curveP384 {
		t.Errorf("CurveID = %d, want %d", parsed.CurveID, curveP384)
	}
	if len(parsed.EphPub) != 97 {
		t.Errorf("EphPub length = %d, want 97", len(parsed.EphPub))
	}
}

// TestHeaderDifferentSlots tests header with different PIV slots.
func TestHeaderDifferentSlots(t *testing.T) {
	slots := []uint32{0x9a, 0x9c, 0x9d, 0x9e}

	for _, slotKey := range slots {
		t.Run("slot "+string(rune('0'+slotKey)), func(t *testing.T) {
			h := createTestHeader(CipherChaCha20)
			h.SlotKey = slotKey

			full, err := h.MarshalFull()
			if err != nil {
				t.Fatalf("MarshalFull failed: %v", err)
			}

			br := bufio.NewReader(bytes.NewReader(full))
			parsed, _, _, err := ParseHeader(br)
			if err != nil {
				t.Fatalf("ParseHeader failed: %v", err)
			}

			if parsed.SlotKey != slotKey {
				t.Errorf("SlotKey = %x, want %x", parsed.SlotKey, slotKey)
			}
		})
	}
}

// TestHeaderChunkSizes tests header with different chunk sizes.
func TestHeaderChunkSizes(t *testing.T) {
	sizes := []uint32{1024, 64 * 1024, 1 << 20, 64 << 20}

	for _, size := range sizes {
		t.Run("chunk size", func(t *testing.T) {
			h := createTestHeader(CipherChaCha20)
			h.ChunkSize = size

			full, err := h.MarshalFull()
			if err != nil {
				t.Fatalf("MarshalFull failed: %v", err)
			}

			br := bufio.NewReader(bytes.NewReader(full))
			parsed, _, _, err := ParseHeader(br)
			if err != nil {
				t.Fatalf("ParseHeader failed: %v", err)
			}

			if parsed.ChunkSize != size {
				t.Errorf("ChunkSize = %d, want %d", parsed.ChunkSize, size)
			}
		})
	}
}

// BenchmarkHeaderMarshal benchmarks header marshaling.
func BenchmarkHeaderMarshal(b *testing.B) {
	h := createTestHeader(CipherChaCha20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.MarshalFull()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHeaderParse benchmarks header parsing.
func BenchmarkHeaderParse(b *testing.B) {
	h := createTestHeader(CipherChaCha20)
	full, err := h.MarshalFull()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		br := bufio.NewReader(bytes.NewReader(full))
		_, _, _, err := ParseHeader(br)
		if err != nil {
			b.Fatal(err)
		}
	}
}
