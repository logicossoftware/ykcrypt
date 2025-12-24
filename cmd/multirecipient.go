/*
Copyright © 2025 Logicos Software

multirecipient.go implements multiple recipient encryption support.

This module provides:
  - Multi-recipient file format (YKCRYPT2)
  - Wrapped key blocks for each recipient
  - Re-wrapping without re-encrypting payload
  - Recipient rotation (add/remove recipients)

File Format for Multi-Recipient (YKCRYPT2):
  - Magic header "YKCRYPT2" (8 bytes)
  - Version (1 byte)
  - CipherID (1 byte)
  - Flags (1 byte)
  - Metadata section (authenticated, optional)
  - Number of recipients (2 bytes)
  - For each recipient:
  - RecipientBlock (slot, curve, ephemeral pub, wrapped key)
  - NoncePrefix + ChunkSize
  - Encrypted chunks (same as YKCRYPT1)

This allows adding/removing recipients by re-wrapping the file key
without decrypting and re-encrypting the entire payload.
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Multi-recipient magic bytes
const magicV2 = "YKCRYPT2"

// Maximum number of recipients per file
const maxRecipients = 256

// MetadataFlags for optional metadata fields
const (
	metaHasFilename  uint16 = 1 << 0 // Original filename preserved
	metaHasTimestamp uint16 = 1 << 1 // Creation timestamp
	metaHasComment   uint16 = 1 << 2 // User comment
)

// Metadata holds authenticated metadata about the encrypted file.
type Metadata struct {
	Flags     uint16    // Which optional fields are present
	Filename  string    // Original filename (if preserved)
	Timestamp time.Time // Encryption timestamp
	Comment   string    // User-provided comment
}

// MarshalMetadata serializes metadata to bytes.
func (m *Metadata) MarshalMetadata() ([]byte, error) {
	var b bytes.Buffer

	// Flags
	if err := binary.Write(&b, binary.LittleEndian, m.Flags); err != nil {
		return nil, err
	}

	// Filename (if present)
	if m.Flags&metaHasFilename != 0 {
		if err := WriteU16Bytes(&b, []byte(m.Filename)); err != nil {
			return nil, err
		}
	}

	// Timestamp (if present)
	if m.Flags&metaHasTimestamp != 0 {
		ts := m.Timestamp.Unix()
		if err := binary.Write(&b, binary.LittleEndian, ts); err != nil {
			return nil, err
		}
	}

	// Comment (if present)
	if m.Flags&metaHasComment != 0 {
		if err := WriteU16Bytes(&b, []byte(m.Comment)); err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

// ParseMetadata deserializes metadata from a reader.
func ParseMetadata(r io.Reader) (*Metadata, error) {
	var m Metadata

	if err := binary.Read(r, binary.LittleEndian, &m.Flags); err != nil {
		return nil, err
	}

	if m.Flags&metaHasFilename != 0 {
		filenameBytes, err := ReadU16Bytes(r)
		if err != nil {
			return nil, err
		}
		m.Filename = string(filenameBytes)
	}

	if m.Flags&metaHasTimestamp != 0 {
		var ts int64
		if err := binary.Read(r, binary.LittleEndian, &ts); err != nil {
			return nil, err
		}
		m.Timestamp = time.Unix(ts, 0)
	}

	if m.Flags&metaHasComment != 0 {
		commentBytes, err := ReadU16Bytes(r)
		if err != nil {
			return nil, err
		}
		m.Comment = string(commentBytes)
	}

	return &m, nil
}

// RecipientBlock contains the wrapped key for one recipient.
type RecipientBlock struct {
	SlotKey    uint32 // PIV slot key identifier
	CurveID    uint8  // Elliptic curve identifier
	EphPub     []byte // Ephemeral public key for this recipient
	Salt       []byte // HKDF salt (16 bytes)
	PassSalt   []byte // Passphrase salt (16 bytes, empty if no passphrase)
	WrapNonce  []byte // Nonce for key wrapping (12 bytes)
	WrappedKey []byte // Encrypted file key
	Flags      uint8  // Per-recipient flags (e.g., has passphrase)
}

// MarshalRecipientBlock serializes a recipient block.
func (rb *RecipientBlock) MarshalRecipientBlock() ([]byte, error) {
	var b bytes.Buffer

	// Slot key (4 bytes)
	if err := binary.Write(&b, binary.LittleEndian, rb.SlotKey); err != nil {
		return nil, err
	}

	// Curve ID (1 byte)
	b.WriteByte(rb.CurveID)

	// Flags (1 byte)
	b.WriteByte(rb.Flags)

	// Ephemeral public key
	if err := WriteU16Bytes(&b, rb.EphPub); err != nil {
		return nil, err
	}

	// Salt
	if err := WriteU16Bytes(&b, rb.Salt); err != nil {
		return nil, err
	}

	// Passphrase salt
	if err := WriteU16Bytes(&b, rb.PassSalt); err != nil {
		return nil, err
	}

	// Wrap nonce (12 bytes fixed)
	if len(rb.WrapNonce) != 12 {
		return nil, fmt.Errorf("wrapNonce must be 12 bytes, got %d", len(rb.WrapNonce))
	}
	b.Write(rb.WrapNonce)

	// Wrapped key
	if err := WriteU16Bytes(&b, rb.WrappedKey); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// ParseRecipientBlock deserializes a recipient block.
func ParseRecipientBlock(r io.Reader) (*RecipientBlock, error) {
	var rb RecipientBlock

	if err := binary.Read(r, binary.LittleEndian, &rb.SlotKey); err != nil {
		return nil, err
	}

	curveID, err := readByte(r)
	if err != nil {
		return nil, err
	}
	rb.CurveID = curveID

	flags, err := readByte(r)
	if err != nil {
		return nil, err
	}
	rb.Flags = flags

	rb.EphPub, err = ReadU16Bytes(r)
	if err != nil {
		return nil, err
	}

	rb.Salt, err = ReadU16Bytes(r)
	if err != nil {
		return nil, err
	}

	rb.PassSalt, err = ReadU16Bytes(r)
	if err != nil {
		return nil, err
	}

	rb.WrapNonce = make([]byte, 12)
	if _, err := io.ReadFull(r, rb.WrapNonce); err != nil {
		return nil, err
	}

	rb.WrappedKey, err = ReadU16Bytes(r)
	if err != nil {
		return nil, err
	}

	return &rb, nil
}

// MultiHeader represents the multi-recipient file header.
type MultiHeader struct {
	Version     uint8             // Format version (2)
	CipherID    uint8             // Cipher identifier
	Flags       uint8             // Global flags
	Metadata    *Metadata         // Authenticated metadata (optional)
	Recipients  []*RecipientBlock // Wrapped keys for each recipient
	NoncePrefix []byte            // Nonce prefix for chunks
	ChunkSize   uint32            // Chunk size
}

// MarshalMultiHeader serializes the complete multi-recipient header.
func (h *MultiHeader) MarshalMultiHeader() ([]byte, error) {
	var b bytes.Buffer

	// Magic
	b.WriteString(magicV2)

	// Version
	b.WriteByte(h.Version)

	// Cipher ID
	b.WriteByte(h.CipherID)

	// Global flags
	b.WriteByte(h.Flags)

	// Metadata (length-prefixed)
	if h.Metadata != nil {
		metaBytes, err := h.Metadata.MarshalMetadata()
		if err != nil {
			return nil, err
		}
		if err := WriteU16Bytes(&b, metaBytes); err != nil {
			return nil, err
		}
	} else {
		// Empty metadata
		if err := WriteU16Bytes(&b, nil); err != nil {
			return nil, err
		}
	}

	// Number of recipients
	if len(h.Recipients) > maxRecipients {
		return nil, fmt.Errorf("too many recipients: %d (max %d)", len(h.Recipients), maxRecipients)
	}
	if err := binary.Write(&b, binary.LittleEndian, uint16(len(h.Recipients))); err != nil {
		return nil, err
	}

	// Each recipient block
	for _, rb := range h.Recipients {
		rbBytes, err := rb.MarshalRecipientBlock()
		if err != nil {
			return nil, err
		}
		if err := WriteU16Bytes(&b, rbBytes); err != nil {
			return nil, err
		}
	}

	// Nonce prefix
	if err := WriteU16Bytes(&b, h.NoncePrefix); err != nil {
		return nil, err
	}

	// Chunk size
	if err := binary.Write(&b, binary.LittleEndian, h.ChunkSize); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// ParseMultiHeader parses a multi-recipient header.
func ParseMultiHeader(br *bufio.Reader) (*MultiHeader, []byte, error) {
	var h MultiHeader
	var full bytes.Buffer

	// Read and verify magic
	m := make([]byte, len(magicV2))
	if _, err := io.ReadFull(br, m); err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	if string(m) != magicV2 {
		return nil, nil, ErrInvalidMagic(string(m))
	}
	full.Write(m)

	// Version
	v, err := br.ReadByte()
	if err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	h.Version = v
	full.WriteByte(v)

	// Cipher ID
	cid, err := br.ReadByte()
	if err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	h.CipherID = cid
	full.WriteByte(cid)

	// Global flags
	flags, err := br.ReadByte()
	if err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	h.Flags = flags
	full.WriteByte(flags)

	// Metadata
	metaBytes, err := ReadU16Bytes(br)
	if err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	WriteU16Bytes(&full, metaBytes)
	if len(metaBytes) > 0 {
		h.Metadata, err = ParseMetadata(bytes.NewReader(metaBytes))
		if err != nil {
			return nil, nil, err
		}
	}

	// Number of recipients
	var numRecipients uint16
	if err := binary.Read(br, binary.LittleEndian, &numRecipients); err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	binary.Write(&full, binary.LittleEndian, numRecipients)

	if numRecipients == 0 {
		return nil, nil, fmt.Errorf("file has no recipients")
	}
	if numRecipients > maxRecipients {
		return nil, nil, fmt.Errorf("too many recipients: %d", numRecipients)
	}

	// Parse each recipient block
	h.Recipients = make([]*RecipientBlock, numRecipients)
	for i := uint16(0); i < numRecipients; i++ {
		rbBytes, err := ReadU16Bytes(br)
		if err != nil {
			return nil, nil, ErrTruncatedHeader(err)
		}
		WriteU16Bytes(&full, rbBytes)

		rb, err := ParseRecipientBlock(bytes.NewReader(rbBytes))
		if err != nil {
			return nil, nil, err
		}
		h.Recipients[i] = rb
	}

	// Nonce prefix
	h.NoncePrefix, err = ReadU16Bytes(br)
	if err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	WriteU16Bytes(&full, h.NoncePrefix)

	// Chunk size
	if err := binary.Read(br, binary.LittleEndian, &h.ChunkSize); err != nil {
		return nil, nil, ErrTruncatedHeader(err)
	}
	binary.Write(&full, binary.LittleEndian, h.ChunkSize)

	return &h, full.Bytes(), nil
}

// Helper to read a single byte
func readByte(r io.Reader) (uint8, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// WrapKeyForRecipient wraps the file key for a single recipient.
func WrapKeyForRecipient(fileKey []byte, recipient Recipient, passphrase string) (*RecipientBlock, error) {
	// Get the curve
	curve, err := CurveFromID(recipient.CurveID)
	if err != nil {
		return nil, err
	}

	// Parse recipient's public key
	recipientPub, err := curve.NewPublicKey(recipient.PubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Generate ephemeral key pair
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Perform ECDH
	sharedSecret, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}

	// Generate cryptographic materials
	salt := MustRand(16)
	wrapNonce := MustRand(12)

	var flags uint8
	var passSalt []byte
	if passphrase != "" {
		flags |= flagHasPassphrase
		passSalt = MustRand(16)
	}

	// Derive wrap key
	wrapKey, err := DeriveWrapKey(sharedSecret, salt, passSalt, passphrase)
	if err != nil {
		return nil, err
	}

	// Create wrap AAD from recipient info
	wrapAAD := makeRecipientAAD(recipient.SlotKey, recipient.CurveID, ephPriv.PublicKey().Bytes())

	// Wrap the file key
	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}
	wrappedKey := wrapAEAD.Seal(nil, wrapNonce, fileKey, wrapAAD)

	return &RecipientBlock{
		SlotKey:    recipient.SlotKey,
		CurveID:    recipient.CurveID,
		EphPub:     ephPriv.PublicKey().Bytes(),
		Salt:       salt,
		PassSalt:   passSalt,
		WrapNonce:  wrapNonce,
		WrappedKey: wrappedKey,
		Flags:      flags,
	}, nil
}

// UnwrapKeyFromBlock attempts to unwrap the file key from a recipient block.
func UnwrapKeyFromBlock(block *RecipientBlock, ecdhFunc func(*ecdh.PublicKey) ([]byte, error), passphrase string) ([]byte, error) {
	// Get the curve
	curve, err := CurveFromID(block.CurveID)
	if err != nil {
		return nil, err
	}

	// Parse ephemeral public key
	ephPub, err := curve.NewPublicKey(block.EphPub)
	if err != nil {
		return nil, err
	}

	// Perform ECDH using the provided function (typically from YubiKey)
	sharedSecret, err := ecdhFunc(ephPub)
	if err != nil {
		return nil, err
	}

	// Derive wrap key
	wrapKey, err := DeriveWrapKey(sharedSecret, block.Salt, block.PassSalt, passphrase)
	if err != nil {
		return nil, err
	}

	// Create wrap AAD
	wrapAAD := makeRecipientAAD(block.SlotKey, block.CurveID, block.EphPub)

	// Unwrap the file key
	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}

	return wrapAEAD.Open(nil, block.WrapNonce, block.WrappedKey, wrapAAD)
}

// makeRecipientAAD creates the AAD for wrapping/unwrapping.
func makeRecipientAAD(slotKey uint32, curveID uint8, ephPub []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, slotKey)
	b.WriteByte(curveID)
	b.Write(ephPub)
	return b.Bytes()
}

// FindMatchingRecipient finds and decrypts for a matching recipient.
func FindMatchingRecipient(
	recipients []*RecipientBlock,
	mySlotKey uint32,
	ecdhFunc func(*ecdh.PublicKey) ([]byte, error),
	getPassphrase func() string,
) ([]byte, *RecipientBlock, error) {
	// First, try to find a recipient that matches our slot
	for _, rb := range recipients {
		if rb.SlotKey == mySlotKey {
			// Check if passphrase is required
			passphrase := ""
			if rb.Flags&flagHasPassphrase != 0 {
				passphrase = getPassphrase()
			}

			fileKey, err := UnwrapKeyFromBlock(rb, ecdhFunc, passphrase)
			if err == nil {
				return fileKey, rb, nil
			}
			// If unwrap failed, this might be a different key in the same slot
			// Continue trying other recipients
		}
	}

	// No matching recipient found
	return nil, nil, ErrNoRecipientMatch()
}
