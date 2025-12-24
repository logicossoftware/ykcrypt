/*
Copyright © 2025 Logicos Software

decrypt.go implements the 'decrypt' command for file decryption.

This module provides file decryption using the YubiKey's private key
to perform ECDH key agreement. The decryption process:

 1. Parse the file header to extract cryptographic parameters
 2. Perform ECDH using the YubiKey (requires PIN + touch)
 3. Derive the wrap key from the shared secret
 4. Optionally incorporate the passphrase if the file was encrypted with one
 5. Unwrap the file key using ChaCha20-Poly1305
 6. Stream-decrypt all chunks using the file key

Security Requirements:
  - YubiKey must be present and contain the matching private key
  - Correct PIV PIN must be entered
  - Physical touch of the YubiKey is required
  - If passphrase was used during encryption, it must be provided
*/
package cmd

import (
	"bufio"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/chacha20poly1305"
)

// decryptCmd represents the 'decrypt' command with full options.
// It reads the slot information from the encrypted file header.
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file using the YubiKey",
	Long: `Decrypt a file using the YubiKey in the slot referenced by the ciphertext.

You will be prompted for the PIV PIN and need to touch the YubiKey.
If the file was encrypted with a passphrase, you will also be prompted for it.

COMMON ERRORS AND SOLUTIONS:

  "smart card error 6982: security status not satisfied"
    You didn't touch the YubiKey in time! After entering your PIN, the YubiKey
    blinks waiting for you to physically touch the gold contact. You have about
    15 seconds before it times out. Try again and touch it promptly.

  "smart card error 63cx: verification failed (x retries remaining)"  
    Wrong PIN! The 'x' shows how many attempts you have left (e.g., 63c2 means
    2 retries). After 3 failed attempts, your PIN will be blocked. If blocked,
    you'll need to use the PUK to reset it (see YubiKey Manager).

  "smart card error 6983: authentication method blocked"
    Your PIN is blocked after too many wrong attempts. Use YubiKey Manager or
    'ykman piv access unblock-pin' with your PUK to reset it.

  "smart card error 6a82: data object or application not found"
    No key exists in this slot. Did you run 'ykcrypt init' first? Or maybe you're
    using a different YubiKey than the one used for encryption.

  "smart card error 6985: conditions of use not satisfied"
    The YubiKey refused the operation. This can happen if touch policy requires
    touch but you didn't touch, or if there's a policy mismatch.

  "no yubikey reader found"
    No YubiKey detected. Make sure it's plugged in. On Linux, ensure pcscd is
    running: 'sudo systemctl start pcscd'

  "this doesn't look like an encrypted file"
    You're trying to decrypt a file that wasn't encrypted with ykcrypt, or it's
    already been decrypted. Check you have the right file!`,
	Example: `  # Decrypt a file
  ykcrypt decrypt --in secrets.txt.ykc --out secrets.txt`,
	Run: runDecrypt,
}

// init registers the 'decrypt' command and configures its command-line flags.
// Required flags: --in, --out
func init() {
	rootCmd.AddCommand(decryptCmd)

	// Input/output file paths (required)
	decryptCmd.Flags().StringP("in", "i", "", "Input file path (required)")
	decryptCmd.Flags().StringP("out", "o", "", "Output file path (required)")

	// Mark required flags
	decryptCmd.MarkFlagRequired("in")
	decryptCmd.MarkFlagRequired("out")
}

// runDecrypt is the command handler for 'decrypt'.
// It extracts flag values and delegates to doDecrypt for the actual work.
func runDecrypt(cmd *cobra.Command, args []string) {
	// Extract flag values
	reader, _ := cmd.Flags().GetString("reader")
	inPath, _ := cmd.Flags().GetString("in")
	outPath, _ := cmd.Flags().GetString("out")

	// Perform decryption
	doDecrypt(reader, inPath, outPath)
}

// doDecrypt performs the actual file decryption.
// This function is shared between the 'decrypt' and 'd' commands.
//
// Parameters:
//   - reader: PC/SC reader name (empty for auto-detect)
//   - inPath: Path to the encrypted input file
//   - outPath: Path for the decrypted output file
//
// The function:
//  1. Parses the encrypted file header
//  2. Opens connection to the YubiKey
//  3. Prompts for PIN and performs ECDH
//  4. Derives the wrap key and unwraps the file key
//  5. Stream-decrypts all chunks
//
// The function exits the program on any error.
func doDecrypt(reader, inPath, outPath string) {
	// Open the encrypted input file
	inF, err := os.Open(inPath)
	if err != nil {
		ExitWithError(err)
	}
	defer inF.Close()

	// Use buffered reader for efficient parsing
	br := bufio.NewReader(inF)

	// Parse the file header to extract cryptographic parameters
	h, fullHeader, wrapAAD, err := ParseHeader(br)
	if err != nil {
		ExitWithError(err)
	}

	// Get the ECDH curve from the curve ID stored in the header
	curve, err := CurveFromID(h.CurveID)
	if err != nil {
		ExitWithError(err)
	}

	// Parse the ephemeral public key from the header
	ephPub, err := curve.NewPublicKey(h.EphPub)
	if err != nil {
		ExitWithError(err)
	}

	// Determine which PIV slot contains the private key
	slot, err := SlotFromKey(h.SlotKey)
	if err != nil {
		ExitWithError(err)
	}

	// Open connection to the YubiKey
	yk, closeFn, err := OpenYubiKey(reader)
	if err != nil {
		ExitWithError(err)
	}
	defer closeFn()

	// Get the certificate from the slot (needed for PrivateKey call)
	cert, err := yk.Certificate(slot)
	if err != nil {
		// Fall back to attestation if no certificate is stored
		cert, err = yk.Attest(slot)
		if err != nil {
			ExitWithError(err)
		}
	}

	// Create PIN prompt handler that caches the PIN for multiple operations
	pin := ""
	auth := MakePINPromptAuth(func() (string, error) {
		if pin != "" {
			return pin, nil // Return cached PIN
		}
		// Prompt user for PIN
		p, err := PromptHidden("PIV PIN: ")
		if err != nil {
			return "", err
		}
		pin = p
		// Inform user to touch the YubiKey
		fmt.Fprintln(os.Stderr, "Touch your YubiKey...")
		return pin, nil
	})

	// Get the private key handle from the YubiKey
	// This doesn't extract the key - it returns a handle for cryptographic operations
	priv, err := yk.PrivateKey(slot, cert.PublicKey, auth)
	if err != nil {
		ExitWithError(err)
	}

	// Type assert to get the ECDH interface
	ecdher, ok := priv.(interface {
		ECDH(peer *ecdh.PublicKey) ([]byte, error)
	})
	if !ok {
		ExitWithErrorMsg("slot private key does not support ECDH; got %T", priv)
	}

	// Perform ECDH to derive the shared secret
	// This operation happens on the YubiKey and requires PIN + touch
	sharedSecret, err := ecdher.ECDH(ephPub)
	if err != nil {
		ExitWithError(err)
	}

	// If the file was encrypted with a passphrase, prompt for it
	passphrase := ""
	if (h.Flags & flagHasPassphrase) != 0 {
		passphrase = MustPromptPassphrase("Passphrase: ")
	}

	// Derive the wrap key from shared secret, salt, and optional passphrase
	wrapKey, err := DeriveWrapKey(sharedSecret, h.Salt, h.PassSalt, passphrase)
	if err != nil {
		ExitWithError(err)
	}

	// Create AEAD cipher for key unwrapping
	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		ExitWithError(err)
	}

	// Unwrap (decrypt and authenticate) the file key
	fileKey, err := wrapAEAD.Open(nil, h.WrapNonce, h.WrappedKey, wrapAAD)
	if err != nil {
		ExitWithError(err)
	}

	// Create the AEAD cipher for file decryption
	fileAEAD, err := NewFileAEAD(fileKey, h.CipherID)
	if err != nil {
		ExitWithError(err)
	}

	// Create output file with restricted permissions
	outF, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		ExitWithError(err)
	}
	defer outF.Close()

	// Use buffered writer for better I/O performance
	bw := bufio.NewWriter(outF)
	defer bw.Flush()

	// Stream-decrypt all chunks
	var chunkIdx uint64
	for {
		// Read chunk length (4 bytes, little-endian)
		var ctLen uint32
		if err := binary.Read(br, binary.LittleEndian, &ctLen); err != nil {
			ExitWithError(fmt.Errorf("reading chunk length: %w", err))
		}

		// Zero length marks the end of the file
		if ctLen == 0 {
			break
		}

		// Read the ciphertext
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(br, ct); err != nil {
			ExitWithError(fmt.Errorf("reading chunk bytes: %w", err))
		}

		// Decrypt and authenticate this chunk
		nonce := MakeChunkNonce(h.NoncePrefix, chunkIdx, h.CipherID)
		pt, err := fileAEAD.Open(nil, nonce, ct, fullHeader)
		if err != nil {
			ExitWithError(err)
		}

		// Write the plaintext
		if _, err := bw.Write(pt); err != nil {
			ExitWithError(err)
		}
		chunkIdx++
	}
}
