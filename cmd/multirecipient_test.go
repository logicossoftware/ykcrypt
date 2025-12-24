/*
Copyright © 2025 Logicos Software

multirecipient_test.go contains unit tests for multi-recipient functionality.
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestMetadataRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		meta *Metadata
	}{
		{
			name: "empty metadata",
			meta: &Metadata{},
		},
		{
			name: "filename only",
			meta: &Metadata{
				Flags:    metaHasFilename,
				Filename: "test-file.txt",
			},
		},
		{
			name: "timestamp only",
			meta: &Metadata{
				Flags:     metaHasTimestamp,
				Timestamp: time.Unix(1735689600, 0),
			},
		},
		{
			name: "all fields",
			meta: &Metadata{
				Flags:     metaHasFilename | metaHasTimestamp | metaHasComment,
				Filename:  "secret-doc.pdf",
				Timestamp: time.Unix(1735689600, 0),
				Comment:   "Confidential document",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.meta.MarshalMetadata()
			if err != nil {
				t.Fatalf("MarshalMetadata failed: %v", err)
			}

			// Parse
			parsed, err := ParseMetadata(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseMetadata failed: %v", err)
			}

			// Compare
			if parsed.Flags != tt.meta.Flags {
				t.Errorf("Flags = %d, want %d", parsed.Flags, tt.meta.Flags)
			}
			if parsed.Filename != tt.meta.Filename {
				t.Errorf("Filename = %q, want %q", parsed.Filename, tt.meta.Filename)
			}
			if tt.meta.Flags&metaHasTimestamp != 0 {
				if !parsed.Timestamp.Equal(tt.meta.Timestamp) {
					t.Errorf("Timestamp = %v, want %v", parsed.Timestamp, tt.meta.Timestamp)
				}
			}
			if parsed.Comment != tt.meta.Comment {
				t.Errorf("Comment = %q, want %q", parsed.Comment, tt.meta.Comment)
			}
		})
	}
}

func TestRecipientBlockRoundTrip(t *testing.T) {
	// Create a recipient block
	ephPub := make([]byte, 65)
	rand.Read(ephPub)
	ephPub[0] = 0x04

	salt := make([]byte, 16)
	rand.Read(salt)

	passSalt := make([]byte, 16)
	rand.Read(passSalt)

	wrapNonce := make([]byte, 12)
	rand.Read(wrapNonce)

	wrappedKey := make([]byte, 48)
	rand.Read(wrappedKey)

	rb := &RecipientBlock{
		SlotKey:    0x9d,
		CurveID:    curveP256,
		Flags:      flagHasPassphrase,
		EphPub:     ephPub,
		Salt:       salt,
		PassSalt:   passSalt,
		WrapNonce:  wrapNonce,
		WrappedKey: wrappedKey,
	}

	// Marshal
	data, err := rb.MarshalRecipientBlock()
	if err != nil {
		t.Fatalf("MarshalRecipientBlock failed: %v", err)
	}

	// Parse
	parsed, err := ParseRecipientBlock(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseRecipientBlock failed: %v", err)
	}

	// Compare
	if parsed.SlotKey != rb.SlotKey {
		t.Errorf("SlotKey = %x, want %x", parsed.SlotKey, rb.SlotKey)
	}
	if parsed.CurveID != rb.CurveID {
		t.Errorf("CurveID = %d, want %d", parsed.CurveID, rb.CurveID)
	}
	if parsed.Flags != rb.Flags {
		t.Errorf("Flags = %d, want %d", parsed.Flags, rb.Flags)
	}
	if !bytes.Equal(parsed.EphPub, rb.EphPub) {
		t.Error("EphPub mismatch")
	}
	if !bytes.Equal(parsed.Salt, rb.Salt) {
		t.Error("Salt mismatch")
	}
	if !bytes.Equal(parsed.PassSalt, rb.PassSalt) {
		t.Error("PassSalt mismatch")
	}
	if !bytes.Equal(parsed.WrapNonce, rb.WrapNonce) {
		t.Error("WrapNonce mismatch")
	}
	if !bytes.Equal(parsed.WrappedKey, rb.WrappedKey) {
		t.Error("WrappedKey mismatch")
	}
}

func TestMultiHeaderRoundTrip(t *testing.T) {
	// Create a multi-recipient header
	noncePrefix := make([]byte, 16)
	rand.Read(noncePrefix)

	// Create recipient blocks
	recipients := make([]*RecipientBlock, 2)
	for i := 0; i < 2; i++ {
		ephPub := make([]byte, 65)
		rand.Read(ephPub)
		ephPub[0] = 0x04

		salt := make([]byte, 16)
		rand.Read(salt)

		wrapNonce := make([]byte, 12)
		rand.Read(wrapNonce)

		wrappedKey := make([]byte, 48)
		rand.Read(wrappedKey)

		recipients[i] = &RecipientBlock{
			SlotKey:    uint32(0x9a + i),
			CurveID:    curveP256,
			EphPub:     ephPub,
			Salt:       salt,
			WrapNonce:  wrapNonce,
			WrappedKey: wrappedKey,
		}
	}

	mh := &MultiHeader{
		Version:  2,
		CipherID: CipherChaCha20,
		Flags:    0,
		Metadata: &Metadata{
			Flags:    metaHasFilename,
			Filename: "test.txt",
		},
		Recipients:  recipients,
		NoncePrefix: noncePrefix,
		ChunkSize:   1 << 20,
	}

	// Marshal
	data, err := mh.MarshalMultiHeader()
	if err != nil {
		t.Fatalf("MarshalMultiHeader failed: %v", err)
	}

	// Verify magic
	if string(data[:8]) != magicV2 {
		t.Errorf("Magic = %q, want %q", string(data[:8]), magicV2)
	}

	// Parse
	br := bufio.NewReader(bytes.NewReader(data))
	parsed, fullHeader, err := ParseMultiHeader(br)
	if err != nil {
		t.Fatalf("ParseMultiHeader failed: %v", err)
	}

	// Compare
	if parsed.Version != mh.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, mh.Version)
	}
	if parsed.CipherID != mh.CipherID {
		t.Errorf("CipherID = %d, want %d", parsed.CipherID, mh.CipherID)
	}
	if len(parsed.Recipients) != len(mh.Recipients) {
		t.Errorf("Recipients count = %d, want %d", len(parsed.Recipients), len(mh.Recipients))
	}
	if parsed.ChunkSize != mh.ChunkSize {
		t.Errorf("ChunkSize = %d, want %d", parsed.ChunkSize, mh.ChunkSize)
	}
	if parsed.Metadata == nil {
		t.Error("Metadata is nil")
	} else if parsed.Metadata.Filename != mh.Metadata.Filename {
		t.Errorf("Metadata.Filename = %q, want %q", parsed.Metadata.Filename, mh.Metadata.Filename)
	}

	// Verify fullHeader matches
	if !bytes.Equal(fullHeader, data) {
		t.Error("fullHeader doesn't match original data")
	}
}

func TestWrapKeyForRecipient(t *testing.T) {
	// Generate a test key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create recipient from public key
	point := elliptic.Marshal(priv.Curve, priv.X, priv.Y)
	recipient := Recipient{
		SlotKey:     0x9d,
		CurveID:     curveP256,
		PubKeyBytes: point,
	}

	// Generate file key
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	// Wrap for recipient
	rb, err := WrapKeyForRecipient(fileKey, recipient, "")
	if err != nil {
		t.Fatalf("WrapKeyForRecipient failed: %v", err)
	}

	// Verify recipient block
	if rb.SlotKey != recipient.SlotKey {
		t.Errorf("SlotKey = %x, want %x", rb.SlotKey, recipient.SlotKey)
	}
	if rb.CurveID != recipient.CurveID {
		t.Errorf("CurveID = %d, want %d", rb.CurveID, recipient.CurveID)
	}
	if len(rb.EphPub) != 65 {
		t.Errorf("EphPub length = %d, want 65", len(rb.EphPub))
	}
	if len(rb.Salt) != 16 {
		t.Errorf("Salt length = %d, want 16", len(rb.Salt))
	}
	if len(rb.WrapNonce) != 12 {
		t.Errorf("WrapNonce length = %d, want 12", len(rb.WrapNonce))
	}
	if len(rb.WrappedKey) != 48 { // 32 bytes + 16 bytes tag
		t.Errorf("WrappedKey length = %d, want 48", len(rb.WrappedKey))
	}
}

func TestWrapAndUnwrapKey(t *testing.T) {
	// Generate a test key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create recipient from public key
	point := elliptic.Marshal(priv.Curve, priv.X, priv.Y)
	recipient := Recipient{
		SlotKey:     0x9d,
		CurveID:     curveP256,
		PubKeyBytes: point,
	}

	// Generate file key
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	tests := []struct {
		name       string
		passphrase string
	}{
		{"without passphrase", ""},
		{"with passphrase", "test-passphrase-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap
			rb, err := WrapKeyForRecipient(fileKey, recipient, tt.passphrase)
			if err != nil {
				t.Fatalf("WrapKeyForRecipient failed: %v", err)
			}

			// Verify passphrase flag
			if tt.passphrase != "" {
				if rb.Flags&flagHasPassphrase == 0 {
					t.Error("Expected HasPassphrase flag to be set")
				}
				if len(rb.PassSalt) != 16 {
					t.Errorf("PassSalt length = %d, want 16", len(rb.PassSalt))
				}
			} else {
				if rb.Flags&flagHasPassphrase != 0 {
					t.Error("HasPassphrase flag should not be set")
				}
			}

			// Create ECDH function from private key
			ecdhPriv, err := priv.ECDH()
			if err != nil {
				t.Fatalf("ECDH() failed: %v", err)
			}

			ecdhFunc := func(peer *ecdh.PublicKey) ([]byte, error) {
				return ecdhPriv.ECDH(peer)
			}

			// Unwrap
			unwrapped, err := UnwrapKeyFromBlock(rb, ecdhFunc, tt.passphrase)
			if err != nil {
				t.Fatalf("UnwrapKeyFromBlock failed: %v", err)
			}

			// Verify
			if !bytes.Equal(unwrapped, fileKey) {
				t.Error("Unwrapped key doesn't match original")
			}
		})
	}
}

func TestUnwrapWithWrongPassphrase(t *testing.T) {
	// Generate a test key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	point := elliptic.Marshal(priv.Curve, priv.X, priv.Y)
	recipient := Recipient{
		SlotKey:     0x9d,
		CurveID:     curveP256,
		PubKeyBytes: point,
	}

	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	// Wrap with passphrase
	rb, err := WrapKeyForRecipient(fileKey, recipient, "correct-passphrase")
	if err != nil {
		t.Fatalf("WrapKeyForRecipient failed: %v", err)
	}

	// Create ECDH function
	ecdhPriv, err := priv.ECDH()
	if err != nil {
		t.Fatalf("ECDH() failed: %v", err)
	}

	ecdhFunc := func(peer *ecdh.PublicKey) ([]byte, error) {
		return ecdhPriv.ECDH(peer)
	}

	// Try to unwrap with wrong passphrase
	_, err = UnwrapKeyFromBlock(rb, ecdhFunc, "wrong-passphrase")
	if err == nil {
		t.Error("Expected error with wrong passphrase")
	}
}

func TestMultipleRecipients(t *testing.T) {
	// Generate two key pairs
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	priv2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create recipients
	point1 := elliptic.Marshal(priv1.Curve, priv1.X, priv1.Y)
	recipient1 := Recipient{SlotKey: 0x9d, CurveID: curveP256, PubKeyBytes: point1}

	point2 := elliptic.Marshal(priv2.Curve, priv2.X, priv2.Y)
	recipient2 := Recipient{SlotKey: 0x9a, CurveID: curveP384, PubKeyBytes: point2}

	// Generate file key
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	// Wrap for both recipients
	rb1, err := WrapKeyForRecipient(fileKey, recipient1, "")
	if err != nil {
		t.Fatalf("WrapKeyForRecipient(1) failed: %v", err)
	}
	rb2, err := WrapKeyForRecipient(fileKey, recipient2, "pass2")
	if err != nil {
		t.Fatalf("WrapKeyForRecipient(2) failed: %v", err)
	}

	// Both should unwrap to the same key
	ecdhPriv1, _ := priv1.ECDH()
	ecdhFunc1 := func(peer *ecdh.PublicKey) ([]byte, error) {
		return ecdhPriv1.ECDH(peer)
	}
	unwrapped1, err := UnwrapKeyFromBlock(rb1, ecdhFunc1, "")
	if err != nil {
		t.Fatalf("UnwrapKeyFromBlock(1) failed: %v", err)
	}

	ecdhPriv2, _ := priv2.ECDH()
	ecdhFunc2 := func(peer *ecdh.PublicKey) ([]byte, error) {
		return ecdhPriv2.ECDH(peer)
	}
	unwrapped2, err := UnwrapKeyFromBlock(rb2, ecdhFunc2, "pass2")
	if err != nil {
		t.Fatalf("UnwrapKeyFromBlock(2) failed: %v", err)
	}

	// Both should match original
	if !bytes.Equal(unwrapped1, fileKey) {
		t.Error("Recipient 1 unwrapped key doesn't match")
	}
	if !bytes.Equal(unwrapped2, fileKey) {
		t.Error("Recipient 2 unwrapped key doesn't match")
	}
}

func TestMaxRecipients(t *testing.T) {
	// Create header with too many recipients
	mh := &MultiHeader{
		Version:     2,
		CipherID:    CipherChaCha20,
		Recipients:  make([]*RecipientBlock, maxRecipients+1),
		NoncePrefix: make([]byte, 16),
		ChunkSize:   1 << 20,
	}

	_, err := mh.MarshalMultiHeader()
	if err == nil {
		t.Error("Expected error for too many recipients")
	}
}

func BenchmarkWrapKeyForRecipient(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point := elliptic.Marshal(priv.Curve, priv.X, priv.Y)
	recipient := Recipient{SlotKey: 0x9d, CurveID: curveP256, PubKeyBytes: point}
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WrapKeyForRecipient(fileKey, recipient, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnwrapKeyFromBlock(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point := elliptic.Marshal(priv.Curve, priv.X, priv.Y)
	recipient := Recipient{SlotKey: 0x9d, CurveID: curveP256, PubKeyBytes: point}
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	rb, _ := WrapKeyForRecipient(fileKey, recipient, "")

	ecdhPriv, _ := priv.ECDH()
	ecdhFunc := func(peer *ecdh.PublicKey) ([]byte, error) {
		return ecdhPriv.ECDH(peer)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnwrapKeyFromBlock(rb, ecdhFunc, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}
