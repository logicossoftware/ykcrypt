/*
Copyright © 2025 Logicos Software

encrypt.go implements the 'encrypt' command for file encryption.

This module provides full-featured file encryption using ECDH key agreement
with a YubiKey-stored public key (or a provided recipient string). The
encryption process:

 1. Generates an ephemeral EC key pair
 2. Performs ECDH with the recipient's public key to derive a shared secret
 3. Uses HKDF to derive a wrap key from the shared secret
 4. Optionally incorporates a passphrase using Argon2id
 5. Generates a random file key and wraps it with ChaCha20-Poly1305
 6. Stream-encrypts the file in chunks using the file key

File Format:
  - Magic header "YKCRYPT1" + version + metadata
  - Ephemeral public key for ECDH
  - Salt values for key derivation
  - Wrapped file key (encrypted with AEAD)
  - Sequence of length-prefixed encrypted chunks
  - Zero-length end marker
*/
package cmd

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/chacha20poly1305"
)

// encryptCmd represents the 'encrypt' command with full options.
// It supports specifying recipient, slot, passphrase, chunk size, and cipher.
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file to a recipient",
	Long: `Encrypt a file to a recipient using ECDH key agreement.

If no recipient is provided, the public key is read from the YubiKey in the specified slot.
This means you can encrypt without the YubiKey if you have the recipient string.`,
	Example: `  # Encrypt using recipient string
  ykcrypt encrypt --recipient "ykcrypt1:..." --in secrets.txt --out secrets.txt.ykc

  # Encrypt using YubiKey (reads public key from slot 9d)
  ykcrypt encrypt --in secrets.txt --out secrets.txt.ykc

  # Encrypt with passphrase as second factor
  ykcrypt encrypt --in secrets.txt --out secrets.txt.ykc --passphrase

  # Encrypt using AES-256-GCM instead of ChaCha20
  ykcrypt encrypt --cipher aes --in secrets.txt --out secrets.txt.ykc`,
	Run: runEncrypt,
}

// init registers the 'encrypt' command and configures all command-line flags.
// Required flags: --in, --out
// Optional flags: --recipient, --slot, --passphrase, --chunk, --cipher
func init() {
	rootCmd.AddCommand(encryptCmd)

	// Input/output file paths (required)
	encryptCmd.Flags().StringP("in", "i", "", "Input file path (required)")
	encryptCmd.Flags().StringP("out", "o", "", "Output file path (required)")

	// Recipient string - if empty, reads from YubiKey
	encryptCmd.Flags().StringP("recipient", "r", "", "Recipient string (from 'ykcrypt export')")

	// PIV slot to read public key from (only used if --recipient is empty)
	encryptCmd.Flags().String("slot", "9d", "Slot to read recipient from if --recipient is empty")

	// Enable passphrase as second factor
	encryptCmd.Flags().BoolP("passphrase", "p", false, "Require a passphrase as second factor")

	// Chunk size for streaming encryption (default 1 MiB)
	encryptCmd.Flags().Int("chunk", 1<<20, "Plaintext chunk size in bytes (default 1MiB)")

	// Cipher selection
	encryptCmd.Flags().StringP("cipher", "c", "chacha", "Cipher: 'chacha' (XChaCha20-Poly1305) or 'aes' (AES-256-GCM)")

	// Mark required flags
	encryptCmd.MarkFlagRequired("in")
	encryptCmd.MarkFlagRequired("out")
}

// runEncrypt is the command handler for 'encrypt'.
// It extracts flag values and delegates to doEncrypt for the actual work.
func runEncrypt(cmd *cobra.Command, args []string) {
	// Extract all flag values
	reader, _ := cmd.Flags().GetString("reader")
	inPath, _ := cmd.Flags().GetString("in")
	outPath, _ := cmd.Flags().GetString("out")
	recipientStr, _ := cmd.Flags().GetString("recipient")
	slotStr, _ := cmd.Flags().GetString("slot")
	usePass, _ := cmd.Flags().GetBool("passphrase")
	chunkSize, _ := cmd.Flags().GetInt("chunk")
	cipherName, _ := cmd.Flags().GetString("cipher")

	// Perform encryption
	doEncrypt(reader, inPath, outPath, recipientStr, slotStr, usePass, chunkSize, cipherName)
}

// doEncrypt performs the actual file encryption.
// This function is shared between the 'encrypt' and 'e' commands.
//
// Parameters:
//   - reader: PC/SC reader name (empty for auto-detect)
//   - inPath: Path to the plaintext input file
//   - outPath: Path for the encrypted output file
//   - recipientStr: Recipient string (empty to read from YubiKey)
//   - slotStr: PIV slot to read public key from
//   - usePass: Whether to require a passphrase
//   - chunkSize: Size of each encryption chunk in bytes
//   - cipherName: Name of the cipher to use ("chacha" or "aes")
//
// The function exits the program on any error.
func doEncrypt(reader, inPath, outPath, recipientStr, slotStr string, usePass bool, chunkSize int, cipherName string) {
	// Validate chunk size (1 byte to 64 MiB)
	if chunkSize <= 0 || chunkSize > (64<<20) {
		ExitWithErrorMsg("invalid --chunk size %d (must be 1..64MiB)", chunkSize)
	}

	// Parse cipher name to cipher ID
	cipherID, err := ParseCipherName(cipherName)
	if err != nil {
		ExitWithError(err)
	}

	// Get recipient public key (from string or YubiKey)
	var r Recipient
	if recipientStr != "" {
		// Parse the provided recipient string
		r, err = ParseRecipient(recipientStr)
		if err != nil {
			ExitWithError(err)
		}
	} else {
		// Read recipient public key from the YubiKey
		slot, err := ParseSlot(slotStr)
		if err != nil {
			ExitWithError(err)
		}
		yk, closeFn, err := OpenYubiKey(reader)
		if err != nil {
			ExitWithError(err)
		}
		defer closeFn()

		// Try to get certificate, fall back to attestation
		cert, err := yk.Certificate(slot)
		if err != nil {
			cert, err = yk.Attest(slot)
			if err != nil {
				ExitWithError(err)
			}
		}
		r, err = RecipientFromCert(slot, cert)
		if err != nil {
			ExitWithError(err)
		}
	}

	// Get the ECDH curve from the curve ID
	curve, err := CurveFromID(r.CurveID)
	if err != nil {
		ExitWithError(err)
	}

	// Parse the recipient's public key
	recipientPub, err := curve.NewPublicKey(r.PubKeyBytes)
	if err != nil {
		ExitWithError(err)
	}

	// Generate ephemeral key pair for ECDH
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		ExitWithError(err)
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()

	// Perform ECDH to derive shared secret
	sharedSecret, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		ExitWithError(err)
	}

	// Generate salts and prepare flags
	salt := MustRand(16) // Salt for HKDF
	psalt := []byte(nil) // Passphrase salt (if used)
	flags := uint8(0)
	var passphrase string

	if usePass {
		// Set passphrase flag and generate passphrase salt
		flags |= flagHasPassphrase
		psalt = MustRand(16)
		passphrase = MustPromptPassphrase("Passphrase: ")
	}

	// Generate cryptographic materials
	fileKey := MustRand(32)                            // Random 256-bit file key
	wrapNonce := MustRand(chacha20poly1305.NonceSize)  // 12-byte nonce for key wrapping
	noncePrefix := MustRand(NoncePrefixSize(cipherID)) // Nonce prefix for chunk encryption

	// Construct the file header
	h := Header{
		Version:     1,
		CurveID:     r.CurveID,
		CipherID:    cipherID,
		SlotKey:     r.SlotKey,
		Flags:       flags,
		EphPub:      ephPubBytes,
		Salt:        salt,
		PassSalt:    psalt,
		NoncePrefix: noncePrefix,
		ChunkSize:   uint32(chunkSize),
		WrapNonce:   wrapNonce,
		WrappedKey:  nil, // Set after wrapping
	}

	// Marshal the header prefix for use as additional authenticated data (AAD)
	wrapAAD, err := h.MarshalPrefixAAD()
	if err != nil {
		ExitWithError(err)
	}

	// Derive the wrap key from shared secret, salt, and optional passphrase
	wrapKey, err := DeriveWrapKey(sharedSecret, salt, psalt, passphrase)
	if err != nil {
		ExitWithError(err)
	}

	// Wrap the file key using ChaCha20-Poly1305
	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		ExitWithError(err)
	}
	h.WrappedKey = wrapAEAD.Seal(nil, wrapNonce, fileKey, wrapAAD)

	// Marshal the complete header
	fullHeader, err := h.MarshalFull()
	if err != nil {
		ExitWithError(err)
	}

	// Open input file for reading
	inF, err := os.Open(inPath)
	if err != nil {
		ExitWithError(err)
	}
	defer inF.Close()

	// Create output file with restricted permissions (owner read/write only)
	outF, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		ExitWithError(err)
	}
	defer outF.Close()

	// Use buffered writer for better I/O performance
	bw := bufio.NewWriter(outF)
	defer bw.Flush()

	// Write the header to the output file
	if _, err := bw.Write(fullHeader); err != nil {
		ExitWithError(err)
	}

	// Create the AEAD cipher for file encryption
	fileAEAD, err := NewFileAEAD(fileKey, cipherID)
	if err != nil {
		ExitWithError(err)
	}

	// Stream-encrypt the file in chunks
	buf := make([]byte, chunkSize)
	var chunkIdx uint64

	for {
		// Read up to chunkSize bytes
		n, rerr := io.ReadAtLeast(inF, buf, 1)
		if rerr == io.EOF {
			break // No more data
		}
		if rerr == io.ErrUnexpectedEOF || rerr == io.EOF {
			// Partial read is OK - n contains the bytes read
		} else if rerr != nil && rerr != io.ErrUnexpectedEOF {
			ExitWithError(rerr)
		}

		// Encrypt this chunk
		pt := buf[:n]
		nonce := MakeChunkNonce(noncePrefix, chunkIdx, cipherID)
		ct := fileAEAD.Seal(nil, nonce, pt, fullHeader)

		// Write chunk length (4 bytes, little-endian) followed by ciphertext
		if err := binary.Write(bw, binary.LittleEndian, uint32(len(ct))); err != nil {
			ExitWithError(err)
		}
		if _, err := bw.Write(ct); err != nil {
			ExitWithError(err)
		}

		chunkIdx++
		if rerr == io.ErrUnexpectedEOF {
			break // Last partial chunk
		}
	}

	// Write end marker (zero-length chunk)
	if err := binary.Write(bw, binary.LittleEndian, uint32(0)); err != nil {
		ExitWithError(err)
	}
}
