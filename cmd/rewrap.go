/*
Copyright © 2025 Logicos Software

rewrap.go implements the 'rewrap' command for recipient management.

This command allows:
  - Adding new recipients to an encrypted file
  - Removing recipients from an encrypted file
  - Re-wrapping the file key without re-encrypting the payload

This is useful for:
  - Key rotation (add new key, remove old key)
  - Sharing files with additional users
  - Revoking access for specific recipients
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/chacha20poly1305"
)

// rewrapCmd represents the 'rewrap' command.
var rewrapCmd = &cobra.Command{
	Use:   "rewrap",
	Short: "Add or remove recipients from an encrypted file",
	Long: `Rewrap an encrypted file to add or remove recipients.

This operation re-wraps the file key for new recipients without
re-encrypting the file contents, which is much faster for large files.

You must have access to one of the current recipients' keys to perform
this operation (your YubiKey must be able to decrypt the file).`,
	Example: `  # Add a new recipient
  ykcrypt rewrap --add "ykcrypt1:9d:1:..." --in secrets.ykc --out secrets-shared.ykc

  # Add multiple recipients
  ykcrypt rewrap --add "ykcrypt1:..." --add "ykcrypt1:..." --in secrets.ykc

  # Remove a recipient (by slot key hex)
  ykcrypt rewrap --remove 9d --in secrets.ykc --out secrets.ykc

  # Add from a file containing recipient strings
  ykcrypt rewrap --add-file recipients.txt --in secrets.ykc`,
	Run: runRewrap,
}

func init() {
	rootCmd.AddCommand(rewrapCmd)

	// Input/output paths
	rewrapCmd.Flags().StringP("in", "i", "", "Input encrypted file (required)")
	rewrapCmd.Flags().StringP("out", "o", "", "Output file (defaults to overwrite input)")

	// Add recipients
	rewrapCmd.Flags().StringArrayP("add", "a", nil, "Add recipient string")
	rewrapCmd.Flags().String("add-file", "", "Add recipients from file (one per line)")

	// Remove recipients
	rewrapCmd.Flags().StringArrayP("remove", "r", nil, "Remove recipient by slot key (hex)")

	// Required flags
	rewrapCmd.MarkFlagRequired("in")
}

func runRewrap(cmd *cobra.Command, args []string) {
	reader, _ := cmd.Flags().GetString("reader")
	inPath, _ := cmd.Flags().GetString("in")
	outPath, _ := cmd.Flags().GetString("out")
	addRecipients, _ := cmd.Flags().GetStringArray("add")
	addFile, _ := cmd.Flags().GetString("add-file")
	removeSlots, _ := cmd.Flags().GetStringArray("remove")

	// Default output to input (in-place)
	if outPath == "" {
		outPath = inPath
	}

	// Collect recipients to add
	recipientsToAdd := make([]Recipient, 0)
	for _, rs := range addRecipients {
		r, err := ParseRecipient(rs)
		if err != nil {
			ExitWithError(ErrInvalidRecipient(err.Error()))
		}
		recipientsToAdd = append(recipientsToAdd, r)
	}

	// Add from file if specified
	if addFile != "" {
		f, err := os.Open(addFile)
		if err != nil {
			ExitWithError(ErrFileNotFound(addFile, err))
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}
			r, err := ParseRecipient(line)
			if err != nil {
				ExitWithError(ErrInvalidRecipient(err.Error()))
			}
			recipientsToAdd = append(recipientsToAdd, r)
		}
		if err := scanner.Err(); err != nil {
			ExitWithError(err)
		}
	}

	// Parse slots to remove
	slotsToRemove := make(map[uint32]bool)
	for _, s := range removeSlots {
		var slotKey uint32
		_, err := fmt.Sscanf(s, "%x", &slotKey)
		if err != nil {
			ExitWithErrorMsg("invalid slot hex %q: %v", s, err)
		}
		slotsToRemove[slotKey] = true
	}

	// Validate we have something to do
	if len(recipientsToAdd) == 0 && len(slotsToRemove) == 0 {
		ExitWithErrorMsg("no recipients to add or remove; use --add or --remove")
	}

	// Open input file
	inF, err := os.Open(inPath)
	if err != nil {
		ExitWithError(ErrFileNotFound(inPath, err))
	}
	defer inF.Close()

	br := bufio.NewReader(inF)

	// Peek at magic to determine format
	magicBytes, err := br.Peek(8)
	if err != nil {
		ExitWithError(ErrTruncatedHeader(err))
	}
	magicStr := string(magicBytes)

	var fileKey []byte
	var existingRecipients []*RecipientBlock
	var cipherID uint8
	var noncePrefix []byte
	var chunkSize uint32
	var originalHeader []byte
	var metadata *Metadata

	if magicStr == magicV2 {
		// Parse multi-recipient header
		mh, fullHeader, err := ParseMultiHeader(br)
		if err != nil {
			ExitWithError(err)
		}
		originalHeader = fullHeader
		existingRecipients = mh.Recipients
		cipherID = mh.CipherID
		noncePrefix = mh.NoncePrefix
		chunkSize = mh.ChunkSize
		metadata = mh.Metadata

		// Decrypt using our YubiKey
		fileKey = decryptWithYubiKey(reader, mh.Recipients)
	} else if magicStr == magic {
		// Parse single-recipient header and convert
		h, fullHeader, wrapAAD, err := ParseHeader(br)
		if err != nil {
			ExitWithError(err)
		}
		originalHeader = fullHeader
		cipherID = h.CipherID
		noncePrefix = h.NoncePrefix
		chunkSize = h.ChunkSize

		// Convert to recipient block
		existingRecipients = []*RecipientBlock{{
			SlotKey:    h.SlotKey,
			CurveID:    h.CurveID,
			EphPub:     h.EphPub,
			Salt:       h.Salt,
			PassSalt:   h.PassSalt,
			WrapNonce:  h.WrapNonce,
			WrappedKey: h.WrappedKey,
			Flags:      h.Flags,
		}}

		// Decrypt using our YubiKey
		fileKey = decryptSingleRecipient(reader, h, wrapAAD)
	} else {
		ExitWithError(ErrInvalidMagic(magicStr))
	}

	// Remove recipients
	if len(slotsToRemove) > 0 {
		filtered := make([]*RecipientBlock, 0, len(existingRecipients))
		for _, rb := range existingRecipients {
			if !slotsToRemove[rb.SlotKey] {
				filtered = append(filtered, rb)
			}
		}
		if len(filtered) == 0 {
			ExitWithErrorMsg("cannot remove all recipients; at least one must remain")
		}
		existingRecipients = filtered
	}

	// Add new recipients
	for _, r := range recipientsToAdd {
		// Check if already exists
		exists := false
		for _, rb := range existingRecipients {
			if rb.SlotKey == r.SlotKey && bytes.Equal(rb.EphPub[:len(r.PubKeyBytes)], r.PubKeyBytes) {
				exists = true
				break
			}
		}
		if exists {
			fmt.Fprintf(os.Stderr, "warning: recipient with slot %02x already exists, skipping\n", r.SlotKey)
			continue
		}

		// Wrap key for new recipient (no passphrase for added recipients)
		rb, err := WrapKeyForRecipient(fileKey, r, "")
		if err != nil {
			ExitWithError(err)
		}
		existingRecipients = append(existingRecipients, rb)
	}

	// Create new header
	newHeader := &MultiHeader{
		Version:     2,
		CipherID:    cipherID,
		Flags:       0,
		Metadata:    metadata,
		Recipients:  existingRecipients,
		NoncePrefix: noncePrefix,
		ChunkSize:   chunkSize,
	}

	newHeaderBytes, err := newHeader.MarshalMultiHeader()
	if err != nil {
		ExitWithError(err)
	}

	// Create output file atomically
	outWriter, err := NewAtomicWriter(outPath, true)
	if err != nil {
		ExitWithError(err)
	}
	defer outWriter.Abort()

	bw := bufio.NewWriter(outWriter)

	// Write new header
	if _, err := bw.Write(newHeaderBytes); err != nil {
		ExitWithError(err)
	}

	// Copy encrypted chunks (they use the same file key, so no re-encryption needed)
	// Note: The chunks are authenticated with the ORIGINAL header as AAD
	// For a full re-wrap, we'd need to re-encrypt chunks with new header AAD
	// For now, we'll re-encrypt the chunks with the new header
	fileAEAD, err := NewFileAEAD(fileKey, cipherID)
	if err != nil {
		ExitWithError(err)
	}

	var chunkIdx uint64
	for {
		// Read chunk length
		var ctLen uint32
		if err := binary.Read(br, binary.LittleEndian, &ctLen); err != nil {
			ExitWithError(fmt.Errorf("reading chunk length: %w", err))
		}

		// Zero length marks end
		if ctLen == 0 {
			break
		}

		// Read ciphertext
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(br, ct); err != nil {
			ExitWithError(fmt.Errorf("reading chunk: %w", err))
		}

		// Decrypt with original header AAD
		nonce := MakeChunkNonce(noncePrefix, chunkIdx, cipherID)
		pt, err := fileAEAD.Open(nil, nonce, ct, originalHeader)
		if err != nil {
			ExitWithError(ErrDecryptionFailed(err))
		}

		// Re-encrypt with new header AAD
		newCt := fileAEAD.Seal(nil, nonce, pt, newHeaderBytes)

		// Write chunk
		if err := binary.Write(bw, binary.LittleEndian, uint32(len(newCt))); err != nil {
			ExitWithError(err)
		}
		if _, err := bw.Write(newCt); err != nil {
			ExitWithError(err)
		}

		chunkIdx++
	}

	// Write end marker
	if err := binary.Write(bw, binary.LittleEndian, uint32(0)); err != nil {
		ExitWithError(err)
	}

	// Flush and commit
	if err := bw.Flush(); err != nil {
		ExitWithError(err)
	}
	if err := outWriter.Commit(); err != nil {
		ExitWithError(err)
	}

	fmt.Fprintf(os.Stderr, "Rewrapped file with %d recipient(s)\n", len(existingRecipients))
}

// decryptWithYubiKey decrypts the file key using the YubiKey for multi-recipient files.
func decryptWithYubiKey(reader string, recipients []*RecipientBlock) []byte {
	yk, closeFn, err := OpenYubiKey(reader)
	if err != nil {
		ExitWithError(ClassifyError(err))
	}
	defer closeFn()

	// Try each recipient until we find a match
	pin := ""
	auth := MakePINPromptAuth(func() (string, error) {
		if pin != "" {
			return pin, nil
		}
		p, err := PromptHidden("PIV PIN: ")
		if err != nil {
			return "", err
		}
		pin = p
		fmt.Fprintln(os.Stderr, "Touch your YubiKey...")
		return pin, nil
	})

	for _, rb := range recipients {
		slot, err := SlotFromKey(rb.SlotKey)
		if err != nil {
			continue // Try next recipient
		}

		cert, err := yk.Certificate(slot)
		if err != nil {
			cert, err = yk.Attest(slot)
			if err != nil {
				continue // Try next recipient
			}
		}

		priv, err := yk.PrivateKey(slot, cert.PublicKey, auth)
		if err != nil {
			continue // Try next recipient
		}

		ecdher, ok := priv.(interface {
			ECDH(peer *ecdh.PublicKey) ([]byte, error)
		})
		if !ok {
			continue // Try next recipient
		}

		// Try to unwrap
		passphrase := ""
		if rb.Flags&flagHasPassphrase != 0 {
			passphrase = MustPromptPassphrase("Passphrase: ")
		}

		fileKey, err := UnwrapKeyFromBlock(rb, ecdher.ECDH, passphrase)
		if err == nil {
			return fileKey
		}
	}

	ExitWithError(ErrNoRecipientMatch())
	return nil
}

// decryptSingleRecipient decrypts the file key from a YKCRYPT1 header.
func decryptSingleRecipient(reader string, h Header, wrapAAD []byte) []byte {
	yk, closeFn, err := OpenYubiKey(reader)
	if err != nil {
		ExitWithError(ClassifyError(err))
	}
	defer closeFn()

	slot, err := SlotFromKey(h.SlotKey)
	if err != nil {
		ExitWithError(err)
	}

	cert, err := yk.Certificate(slot)
	if err != nil {
		cert, err = yk.Attest(slot)
		if err != nil {
			ExitWithError(ClassifyError(err))
		}
	}

	pin := ""
	auth := piv.KeyAuth{
		PINPrompt: func() (string, error) {
			if pin != "" {
				return pin, nil
			}
			p, err := PromptHidden("PIV PIN: ")
			if err != nil {
				return "", err
			}
			pin = p
			fmt.Fprintln(os.Stderr, "Touch your YubiKey...")
			return pin, nil
		},
	}

	priv, err := yk.PrivateKey(slot, cert.PublicKey, auth)
	if err != nil {
		ExitWithError(ClassifyError(err))
	}

	ecdher, ok := priv.(interface {
		ECDH(peer *ecdh.PublicKey) ([]byte, error)
	})
	if !ok {
		ExitWithErrorMsg("slot private key does not support ECDH")
	}

	curve, err := CurveFromID(h.CurveID)
	if err != nil {
		ExitWithError(err)
	}

	ephPub, err := curve.NewPublicKey(h.EphPub)
	if err != nil {
		ExitWithError(err)
	}

	sharedSecret, err := ecdher.ECDH(ephPub)
	if err != nil {
		ExitWithError(ClassifyError(err))
	}

	passphrase := ""
	if h.Flags&flagHasPassphrase != 0 {
		passphrase = MustPromptPassphrase("Passphrase: ")
	}

	wrapKey, err := DeriveWrapKey(sharedSecret, h.Salt, h.PassSalt, passphrase)
	if err != nil {
		ExitWithError(err)
	}

	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		ExitWithError(err)
	}

	fileKey, err := wrapAEAD.Open(nil, h.WrapNonce, h.WrappedKey, wrapAAD)
	if err != nil {
		ExitWithError(ErrKeyUnwrapFailed(err))
	}

	return fileKey
}
