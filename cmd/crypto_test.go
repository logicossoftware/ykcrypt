/*
Copyright © 2025 Logicos Software

crypto_test.go contains unit tests for cryptographic functions in utils.go.

These tests cover:
  - Key derivation (DeriveWrapKey)
  - AEAD encryption/decryption
  - Chunk encryption round-trips
  - Certificate generation (MakeContainerCert)
*/
package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestDeriveWrapKey tests the DeriveWrapKey function.
func TestDeriveWrapKey(t *testing.T) {
	// Generate a test shared secret
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	salt := make([]byte, 16)
	rand.Read(salt)

	t.Run("without passphrase", func(t *testing.T) {
		key, err := DeriveWrapKey(sharedSecret, salt, nil, "")
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}

		// Key should be 32 bytes
		if len(key) != 32 {
			t.Errorf("Key length = %d, want 32", len(key))
		}

		// Same inputs should produce same key
		key2, err := DeriveWrapKey(sharedSecret, salt, nil, "")
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}
		if !bytes.Equal(key, key2) {
			t.Error("Same inputs should produce same key")
		}
	})

	t.Run("with passphrase", func(t *testing.T) {
		passSalt := make([]byte, 16)
		rand.Read(passSalt)
		passphrase := "my-secret-passphrase"

		key, err := DeriveWrapKey(sharedSecret, salt, passSalt, passphrase)
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}

		// Key should be 32 bytes
		if len(key) != 32 {
			t.Errorf("Key length = %d, want 32", len(key))
		}

		// Same inputs should produce same key
		key2, err := DeriveWrapKey(sharedSecret, salt, passSalt, passphrase)
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}
		if !bytes.Equal(key, key2) {
			t.Error("Same inputs should produce same key")
		}
	})

	t.Run("different passphrases produce different keys", func(t *testing.T) {
		passSalt := make([]byte, 16)
		rand.Read(passSalt)

		key1, err := DeriveWrapKey(sharedSecret, salt, passSalt, "passphrase1")
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}

		key2, err := DeriveWrapKey(sharedSecret, salt, passSalt, "passphrase2")
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}

		if bytes.Equal(key1, key2) {
			t.Error("Different passphrases should produce different keys")
		}
	})

	t.Run("passphrase vs no passphrase", func(t *testing.T) {
		passSalt := make([]byte, 16)
		rand.Read(passSalt)

		keyWithPass, err := DeriveWrapKey(sharedSecret, salt, passSalt, "passphrase")
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}

		keyNoPass, err := DeriveWrapKey(sharedSecret, salt, nil, "")
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}

		if bytes.Equal(keyWithPass, keyNoPass) {
			t.Error("Key with passphrase should differ from key without")
		}
	})

	t.Run("error when passphrase without passSalt", func(t *testing.T) {
		_, err := DeriveWrapKey(sharedSecret, salt, nil, "passphrase")
		if err == nil {
			t.Error("Expected error when passphrase provided without passSalt")
		}
	})

	t.Run("error when passphrase with empty passSalt", func(t *testing.T) {
		_, err := DeriveWrapKey(sharedSecret, salt, []byte{}, "passphrase")
		if err == nil {
			t.Error("Expected error when passphrase provided with empty passSalt")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		salt1 := make([]byte, 16)
		salt2 := make([]byte, 16)
		rand.Read(salt1)
		rand.Read(salt2)

		key1, _ := DeriveWrapKey(sharedSecret, salt1, nil, "")
		key2, _ := DeriveWrapKey(sharedSecret, salt2, nil, "")

		if bytes.Equal(key1, key2) {
			t.Error("Different salts should produce different keys")
		}
	})

	t.Run("different shared secrets produce different keys", func(t *testing.T) {
		secret1 := make([]byte, 32)
		secret2 := make([]byte, 32)
		rand.Read(secret1)
		rand.Read(secret2)

		key1, _ := DeriveWrapKey(secret1, salt, nil, "")
		key2, _ := DeriveWrapKey(secret2, salt, nil, "")

		if bytes.Equal(key1, key2) {
			t.Error("Different shared secrets should produce different keys")
		}
	})
}

// TestChunkEncryptionRoundTrip tests full chunk encryption/decryption cycle.
func TestChunkEncryptionRoundTrip(t *testing.T) {
	// Generate file key
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	// Test with both ciphers
	ciphers := []uint8{CipherChaCha20, CipherAES256}

	// Various chunk sizes to test
	chunkSizes := []int{16, 100, 1024, 64 * 1024}

	// Header bytes for AAD
	header := make([]byte, 128)
	rand.Read(header)

	for _, cipherID := range ciphers {
		for _, chunkSize := range chunkSizes {
			t.Run(CipherName(cipherID)+"/"+string(rune('0'+chunkSize/1024))+"KB", func(t *testing.T) {
				// Create AEAD
				aead, err := NewFileAEAD(fileKey, cipherID)
				if err != nil {
					t.Fatalf("NewFileAEAD failed: %v", err)
				}

				// Generate nonce prefix
				noncePrefix := make([]byte, NoncePrefixSize(cipherID))
				rand.Read(noncePrefix)

				// Create plaintext
				plaintext := make([]byte, chunkSize)
				rand.Read(plaintext)

				// Encrypt
				nonce := MakeChunkNonce(noncePrefix, 0, cipherID)
				ciphertext := aead.Seal(nil, nonce, plaintext, header)

				// Decrypt
				decrypted, err := aead.Open(nil, nonce, ciphertext, header)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}

				// Verify
				if !bytes.Equal(decrypted, plaintext) {
					t.Error("Decrypted text doesn't match plaintext")
				}
			})
		}
	}
}

// TestChunkNonceUniqueness tests that different chunk indices produce unique nonces.
func TestChunkNonceUniqueness(t *testing.T) {
	ciphers := []uint8{CipherChaCha20, CipherAES256}

	for _, cipherID := range ciphers {
		t.Run(CipherName(cipherID), func(t *testing.T) {
			noncePrefix := make([]byte, NoncePrefixSize(cipherID))
			rand.Read(noncePrefix)

			// Generate nonces for several chunk indices
			nonces := make(map[string]bool)
			for idx := uint64(0); idx < 1000; idx++ {
				nonce := MakeChunkNonce(noncePrefix, idx, cipherID)
				nonceStr := string(nonce)
				if nonces[nonceStr] {
					t.Errorf("Duplicate nonce at index %d", idx)
				}
				nonces[nonceStr] = true
			}
		})
	}
}

// TestMakeContainerCert tests the MakeContainerCert function.
func TestMakeContainerCert(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			// Generate a key pair
			priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			cn := "test-cert"

			// Create certificate
			der, cert, err := MakeContainerCert(&priv.PublicKey, cn)
			if err != nil {
				t.Fatalf("MakeContainerCert failed: %v", err)
			}

			// Verify DER bytes are not empty
			if len(der) == 0 {
				t.Error("DER bytes should not be empty")
			}

			// Verify certificate is not nil
			if cert == nil {
				t.Fatal("Certificate should not be nil")
			}

			// Verify common name
			if cert.Subject.CommonName != cn {
				t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, cn)
			}

			// Verify public key matches
			certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("Certificate public key is %T, expected *ecdsa.PublicKey", cert.PublicKey)
			}

			if certPub.X.Cmp(priv.PublicKey.X) != 0 || certPub.Y.Cmp(priv.PublicKey.Y) != 0 {
				t.Error("Certificate public key doesn't match input key")
			}

			// Verify key usage includes KeyAgreement
			// x509.KeyUsageKeyAgreement is the 5th bit (value 16)
			if cert.KeyUsage&16 == 0 {
				t.Errorf("Certificate should have KeyAgreement key usage, got %d", cert.KeyUsage)
			}

			// Verify validity period
			if cert.NotBefore.IsZero() {
				t.Error("NotBefore should not be zero")
			}
			if cert.NotAfter.IsZero() {
				t.Error("NotAfter should not be zero")
			}
			if !cert.NotAfter.After(cert.NotBefore) {
				t.Error("NotAfter should be after NotBefore")
			}
		})
	}
}

// TestAuthenticationIntegrity tests that tampering is detected.
func TestAuthenticationIntegrity(t *testing.T) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	header := make([]byte, 64)
	rand.Read(header)

	plaintext := []byte("This is sensitive data that must be authenticated")

	ciphers := []uint8{CipherChaCha20, CipherAES256}

	for _, cipherID := range ciphers {
		t.Run(CipherName(cipherID), func(t *testing.T) {
			aead, err := NewFileAEAD(fileKey, cipherID)
			if err != nil {
				t.Fatalf("NewFileAEAD failed: %v", err)
			}

			noncePrefix := make([]byte, NoncePrefixSize(cipherID))
			rand.Read(noncePrefix)
			nonce := MakeChunkNonce(noncePrefix, 0, cipherID)

			ciphertext := aead.Seal(nil, nonce, plaintext, header)

			// Tamper with ciphertext
			t.Run("tampered ciphertext", func(t *testing.T) {
				tampered := make([]byte, len(ciphertext))
				copy(tampered, ciphertext)
				tampered[len(tampered)/2] ^= 0xFF

				_, err := aead.Open(nil, nonce, tampered, header)
				if err == nil {
					t.Error("Tampered ciphertext should fail authentication")
				}
			})

			// Tamper with header (AAD)
			t.Run("tampered AAD", func(t *testing.T) {
				tamperedHeader := make([]byte, len(header))
				copy(tamperedHeader, header)
				tamperedHeader[0] ^= 0xFF

				_, err := aead.Open(nil, nonce, ciphertext, tamperedHeader)
				if err == nil {
					t.Error("Tampered AAD should fail authentication")
				}
			})

			// Wrong nonce
			t.Run("wrong nonce", func(t *testing.T) {
				wrongNonce := MakeChunkNonce(noncePrefix, 1, cipherID)

				_, err := aead.Open(nil, wrongNonce, ciphertext, header)
				if err == nil {
					t.Error("Wrong nonce should fail authentication")
				}
			})

			// Wrong key
			t.Run("wrong key", func(t *testing.T) {
				wrongKey := make([]byte, 32)
				rand.Read(wrongKey)

				wrongAEAD, _ := NewFileAEAD(wrongKey, cipherID)
				_, err := wrongAEAD.Open(nil, nonce, ciphertext, header)
				if err == nil {
					t.Error("Wrong key should fail authentication")
				}
			})
		})
	}
}

// TestKeyDerivationDeterminism tests that key derivation is deterministic.
func TestKeyDerivationDeterminism(t *testing.T) {
	sharedSecret := make([]byte, 32)
	salt := make([]byte, 16)
	passSalt := make([]byte, 16)
	passphrase := "test-passphrase"

	rand.Read(sharedSecret)
	rand.Read(salt)
	rand.Read(passSalt)

	// Derive key multiple times
	keys := make([][]byte, 10)
	for i := range keys {
		key, err := DeriveWrapKey(sharedSecret, salt, passSalt, passphrase)
		if err != nil {
			t.Fatalf("DeriveWrapKey failed: %v", err)
		}
		keys[i] = key
	}

	// All keys should be identical
	for i := 1; i < len(keys); i++ {
		if !bytes.Equal(keys[0], keys[i]) {
			t.Errorf("Key %d differs from key 0", i)
		}
	}
}

// TestLargeChunkEncryption tests encryption of large chunks.
func TestLargeChunkEncryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large chunk test in short mode")
	}

	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	header := make([]byte, 128)
	rand.Read(header)

	// Test with 1 MiB chunk (default size)
	chunkSize := 1 << 20
	plaintext := make([]byte, chunkSize)
	rand.Read(plaintext)

	ciphers := []uint8{CipherChaCha20, CipherAES256}

	for _, cipherID := range ciphers {
		t.Run(CipherName(cipherID), func(t *testing.T) {
			aead, err := NewFileAEAD(fileKey, cipherID)
			if err != nil {
				t.Fatalf("NewFileAEAD failed: %v", err)
			}

			noncePrefix := make([]byte, NoncePrefixSize(cipherID))
			rand.Read(noncePrefix)
			nonce := MakeChunkNonce(noncePrefix, 0, cipherID)

			// Encrypt
			ciphertext := aead.Seal(nil, nonce, plaintext, header)

			// Verify ciphertext is larger (includes auth tag)
			if len(ciphertext) <= len(plaintext) {
				t.Error("Ciphertext should be larger than plaintext")
			}

			// Decrypt
			decrypted, err := aead.Open(nil, nonce, ciphertext, header)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("Decrypted data doesn't match plaintext")
			}
		})
	}
}

// BenchmarkDeriveWrapKey benchmarks key derivation.
func BenchmarkDeriveWrapKey(b *testing.B) {
	sharedSecret := make([]byte, 32)
	salt := make([]byte, 16)
	rand.Read(sharedSecret)
	rand.Read(salt)

	b.Run("without passphrase", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := DeriveWrapKey(sharedSecret, salt, nil, "")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("with passphrase", func(b *testing.B) {
		passSalt := make([]byte, 16)
		rand.Read(passSalt)
		passphrase := "benchmark-passphrase"

		for i := 0; i < b.N; i++ {
			_, err := DeriveWrapKey(sharedSecret, salt, passSalt, passphrase)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkChunkEncryption benchmarks chunk encryption.
func BenchmarkChunkEncryption(b *testing.B) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	header := make([]byte, 128)
	rand.Read(header)

	chunkSize := 1 << 20 // 1 MiB
	plaintext := make([]byte, chunkSize)
	rand.Read(plaintext)

	ciphers := []struct {
		name     string
		cipherID uint8
	}{
		{"ChaCha20", CipherChaCha20},
		{"AES-256-GCM", CipherAES256},
	}

	for _, c := range ciphers {
		b.Run(c.name, func(b *testing.B) {
			aead, _ := NewFileAEAD(fileKey, c.cipherID)
			noncePrefix := make([]byte, NoncePrefixSize(c.cipherID))
			rand.Read(noncePrefix)

			b.SetBytes(int64(chunkSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				nonce := MakeChunkNonce(noncePrefix, uint64(i), c.cipherID)
				aead.Seal(nil, nonce, plaintext, header)
			}
		})
	}
}

// BenchmarkChunkDecryption benchmarks chunk decryption.
func BenchmarkChunkDecryption(b *testing.B) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	header := make([]byte, 128)
	rand.Read(header)

	chunkSize := 1 << 20 // 1 MiB
	plaintext := make([]byte, chunkSize)
	rand.Read(plaintext)

	ciphers := []struct {
		name     string
		cipherID uint8
	}{
		{"ChaCha20", CipherChaCha20},
		{"AES-256-GCM", CipherAES256},
	}

	for _, c := range ciphers {
		b.Run(c.name, func(b *testing.B) {
			aead, _ := NewFileAEAD(fileKey, c.cipherID)
			noncePrefix := make([]byte, NoncePrefixSize(c.cipherID))
			rand.Read(noncePrefix)
			nonce := MakeChunkNonce(noncePrefix, 0, c.cipherID)

			ciphertext := aead.Seal(nil, nonce, plaintext, header)

			b.SetBytes(int64(chunkSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := aead.Open(nil, nonce, ciphertext, header)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
