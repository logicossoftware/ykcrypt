/*
Copyright © 2025 Logicos Software

errors.go implements structured error types for better UX.

This module provides:
  - Categorized error types (YubiKey, File, Crypto, Input)
  - User-friendly error messages with troubleshooting hints
  - Error wrapping with context preservation
  - Retry suggestions for transient errors
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrorCategory represents the type of error for classification.
type ErrorCategory int

const (
	// ErrCategoryUnknown for unclassified errors.
	ErrCategoryUnknown ErrorCategory = iota
	// ErrCategoryYubiKey for YubiKey-related errors.
	ErrCategoryYubiKey
	// ErrCategoryFile for file system errors.
	ErrCategoryFile
	// ErrCategoryCrypto for cryptographic errors.
	ErrCategoryCrypto
	// ErrCategoryInput for user input validation errors.
	ErrCategoryInput
	// ErrCategoryFormat for file format errors.
	ErrCategoryFormat
)

// String returns a human-readable category name.
func (c ErrorCategory) String() string {
	switch c {
	case ErrCategoryYubiKey:
		return "YubiKey"
	case ErrCategoryFile:
		return "File"
	case ErrCategoryCrypto:
		return "Cryptographic"
	case ErrCategoryInput:
		return "Input"
	case ErrCategoryFormat:
		return "Format"
	default:
		return "Unknown"
	}
}

// YKCryptError is a structured error with category, message, and hints.
type YKCryptError struct {
	Category    ErrorCategory
	Message     string
	Hint        string
	Cause       error
	IsRetryable bool
}

// Error implements the error interface.
func (e *YKCryptError) Error() string {
	var b strings.Builder
	b.WriteString(e.Message)
	if e.Cause != nil {
		b.WriteString(": ")
		b.WriteString(e.Cause.Error())
	}
	return b.String()
}

// Unwrap returns the underlying cause for error chain inspection.
func (e *YKCryptError) Unwrap() error {
	return e.Cause
}

// FullError returns the error with hint if available.
func (e *YKCryptError) FullError() string {
	var b strings.Builder
	b.WriteString(e.Message)
	if e.Cause != nil {
		b.WriteString(": ")
		b.WriteString(e.Cause.Error())
	}
	if e.Hint != "" {
		b.WriteString("\n\nHint: ")
		b.WriteString(e.Hint)
	}
	return b.String()
}

// Common error constructors for YubiKey errors.

// ErrYubiKeyNotFound indicates no YubiKey was detected.
func ErrYubiKeyNotFound() *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryYubiKey,
		Message:  "no YubiKey detected",
		Hint:     "Make sure your YubiKey is plugged in. On Linux, ensure pcscd is running: 'sudo systemctl start pcscd'",
	}
}

// ErrYubiKeyTouchTimeout indicates the user didn't touch in time.
func ErrYubiKeyTouchTimeout(cause error) *YKCryptError {
	return &YKCryptError{
		Category:    ErrCategoryYubiKey,
		Message:     "YubiKey touch timeout",
		Hint:        "After entering your PIN, the YubiKey blinks waiting for you to physically touch the gold contact. You have about 15 seconds. Try again and touch it promptly.",
		Cause:       cause,
		IsRetryable: true,
	}
}

// ErrYubiKeyWrongPIN indicates incorrect PIN with remaining retries.
func ErrYubiKeyWrongPIN(retries int, cause error) *YKCryptError {
	hint := fmt.Sprintf("Wrong PIN! You have %d attempts remaining. After 3 failed attempts, your PIN will be blocked.", retries)
	if retries <= 1 {
		hint = "Wrong PIN! This is your LAST attempt. If you enter the wrong PIN again, it will be blocked and you'll need the PUK to reset it."
	}
	return &YKCryptError{
		Category:    ErrCategoryYubiKey,
		Message:     fmt.Sprintf("PIN verification failed (%d retries remaining)", retries),
		Hint:        hint,
		Cause:       cause,
		IsRetryable: true,
	}
}

// ErrYubiKeyPINBlocked indicates the PIN is blocked.
func ErrYubiKeyPINBlocked(cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryYubiKey,
		Message:  "PIN is blocked",
		Hint:     "Your PIN is blocked after too many wrong attempts. Use YubiKey Manager or 'ykman piv access unblock-pin' with your PUK to reset it.",
		Cause:    cause,
	}
}

// ErrYubiKeySlotEmpty indicates no key exists in the slot.
func ErrYubiKeySlotEmpty(slot string, cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryYubiKey,
		Message:  fmt.Sprintf("no key in slot %s", slot),
		Hint:     "No key exists in this slot. Did you run 'ykcrypt init' first? Or maybe you're using a different YubiKey than the one used for encryption.",
		Cause:    cause,
	}
}

// ErrYubiKeyConditionsNotSatisfied indicates policy requirements weren't met.
func ErrYubiKeyConditionsNotSatisfied(cause error) *YKCryptError {
	return &YKCryptError{
		Category:    ErrCategoryYubiKey,
		Message:     "operation conditions not satisfied",
		Hint:        "The YubiKey refused the operation. This can happen if touch policy requires touch but you didn't touch, or if there's a policy mismatch.",
		Cause:       cause,
		IsRetryable: true,
	}
}

// Common error constructors for File errors.

// ErrFileNotFound indicates the file doesn't exist.
func ErrFileNotFound(path string, cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFile,
		Message:  fmt.Sprintf("file not found: %s", path),
		Hint:     "Check that the file path is correct and the file exists.",
		Cause:    cause,
	}
}

// ErrFilePermission indicates permission denied.
func ErrFilePermission(path string, cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFile,
		Message:  fmt.Sprintf("permission denied: %s", path),
		Hint:     "Check that you have read/write permissions for this file and its directory.",
		Cause:    cause,
	}
}

// ErrFileAlreadyExists indicates the output file already exists.
func ErrFileAlreadyExists(path string) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFile,
		Message:  fmt.Sprintf("output file already exists: %s", path),
		Hint:     "Use a different output path or delete the existing file first.",
	}
}

// ErrAtomicWriteFailed indicates atomic write operation failed.
func ErrAtomicWriteFailed(path string, cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFile,
		Message:  fmt.Sprintf("atomic write failed for: %s", path),
		Hint:     "The temporary file could not be renamed to the final path. Check disk space and permissions.",
		Cause:    cause,
	}
}

// Common error constructors for Crypto errors.

// ErrDecryptionFailed indicates decryption/authentication failed.
func ErrDecryptionFailed(cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryCrypto,
		Message:  "decryption failed",
		Hint:     "The file may be corrupted, or you're using the wrong YubiKey/passphrase. If a passphrase was used during encryption, make sure you enter the same one.",
		Cause:    cause,
	}
}

// ErrKeyUnwrapFailed indicates the file key couldn't be unwrapped.
func ErrKeyUnwrapFailed(cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryCrypto,
		Message:  "failed to unwrap file key",
		Hint:     "This usually means the wrong YubiKey or passphrase was used. The file may have been encrypted for a different recipient.",
		Cause:    cause,
	}
}

// ErrUnsupportedCurve indicates an unsupported elliptic curve.
func ErrUnsupportedCurve(curveID uint8) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryCrypto,
		Message:  fmt.Sprintf("unsupported curve ID: %d", curveID),
		Hint:     "This file was encrypted with a curve not supported by this version. Supported curves: P-256, P-384.",
	}
}

// ErrUnsupportedCipher indicates an unsupported cipher.
func ErrUnsupportedCipher(cipherID uint8) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryCrypto,
		Message:  fmt.Sprintf("unsupported cipher ID: %d", cipherID),
		Hint:     "This file was encrypted with a cipher not supported by this version. Supported ciphers: XChaCha20-Poly1305, AES-256-GCM.",
	}
}

// Common error constructors for Format errors.

// ErrInvalidMagic indicates the file doesn't have valid magic bytes.
func ErrInvalidMagic(got string) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFormat,
		Message:  fmt.Sprintf("not a ykcrypt encrypted file (expected magic %q, got %q)", magic, got),
		Hint:     "This file wasn't encrypted with ykcrypt, or it's already been decrypted. Check you have the right file!",
	}
}

// ErrInvalidVersion indicates an unsupported file format version.
func ErrInvalidVersion(version uint8) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFormat,
		Message:  fmt.Sprintf("unsupported file format version: %d", version),
		Hint:     "This file was created with a newer version of ykcrypt. Please upgrade to the latest version.",
	}
}

// ErrTruncatedHeader indicates the file header is incomplete.
func ErrTruncatedHeader(cause error) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFormat,
		Message:  "truncated file header",
		Hint:     "The encrypted file appears to be truncated or corrupted. The file may have been partially transferred or damaged.",
		Cause:    cause,
	}
}

// ErrNoRecipientMatch indicates none of the recipients match this YubiKey.
func ErrNoRecipientMatch() *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryFormat,
		Message:  "no matching recipient found",
		Hint:     "This file wasn't encrypted for this YubiKey. Check if you have the correct YubiKey or if you were added as a recipient.",
	}
}

// Common error constructors for Input errors.

// ErrInvalidRecipient indicates an invalid recipient string.
func ErrInvalidRecipient(details string) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryInput,
		Message:  "invalid recipient string",
		Hint:     fmt.Sprintf("The recipient string format is 'ykcrypt1:<slotHex>:<curveId>:<base64PublicKey>'. %s", details),
	}
}

// ErrEmptyPassphrase indicates an empty passphrase was entered.
func ErrEmptyPassphrase() *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryInput,
		Message:  "empty passphrase not allowed",
		Hint:     "You must enter a passphrase when using the --passphrase flag. Press Ctrl+C to cancel if you don't want to use a passphrase.",
	}
}

// ErrInvalidChunkSize indicates an invalid chunk size.
func ErrInvalidChunkSize(size int) *YKCryptError {
	return &YKCryptError{
		Category: ErrCategoryInput,
		Message:  fmt.Sprintf("invalid chunk size: %d", size),
		Hint:     "Chunk size must be between 1 byte and 64 MiB.",
	}
}

// ClassifyError attempts to categorize a generic error into a YKCryptError.
// It inspects error messages for known patterns from the piv-go library.
func ClassifyError(err error) *YKCryptError {
	if err == nil {
		return nil
	}

	// Check if it's already a YKCryptError
	var yke *YKCryptError
	if errors.As(err, &yke) {
		return yke
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	// Check for YubiKey/smart card errors
	if strings.Contains(errLower, "yubikey") || strings.Contains(errLower, "smart card") || strings.Contains(errLower, "piv") {
		// Touch timeout (security status not satisfied)
		if strings.Contains(errStr, "6982") || strings.Contains(errLower, "security status not satisfied") {
			return ErrYubiKeyTouchTimeout(err)
		}

		// Wrong PIN (63cx where x is retries remaining)
		if strings.Contains(errStr, "63c") {
			// Extract retries from error code
			retries := 3 // default
			for i := 0; i <= 9; i++ {
				if strings.Contains(errStr, fmt.Sprintf("63c%d", i)) {
					retries = i
					break
				}
			}
			return ErrYubiKeyWrongPIN(retries, err)
		}

		// PIN blocked
		if strings.Contains(errStr, "6983") || strings.Contains(errLower, "authentication method blocked") {
			return ErrYubiKeyPINBlocked(err)
		}

		// Slot empty / data not found
		if strings.Contains(errStr, "6a82") || strings.Contains(errLower, "data object or application not found") {
			return ErrYubiKeySlotEmpty("unknown", err)
		}

		// Conditions not satisfied
		if strings.Contains(errStr, "6985") || strings.Contains(errLower, "conditions of use not satisfied") {
			return ErrYubiKeyConditionsNotSatisfied(err)
		}

		// No YubiKey found
		if strings.Contains(errLower, "no yubikey") || strings.Contains(errLower, "no reader") {
			return ErrYubiKeyNotFound()
		}
	}

	// Check for file errors
	if strings.Contains(errLower, "no such file") || strings.Contains(errLower, "file not found") {
		return ErrFileNotFound("", err)
	}
	if strings.Contains(errLower, "permission denied") || strings.Contains(errLower, "access denied") {
		return ErrFilePermission("", err)
	}

	// Check for crypto errors
	if strings.Contains(errLower, "message authentication failed") || strings.Contains(errLower, "authentication failed") {
		return ErrDecryptionFailed(err)
	}

	// Return a generic wrapped error
	return &YKCryptError{
		Category: ErrCategoryUnknown,
		Message:  err.Error(),
		Cause:    err,
	}
}

// ExitWithClassifiedError prints a classified error with hints and exits.
func ExitWithClassifiedError(err error) {
	if err == nil {
		return
	}
	yke := ClassifyError(err)
	fmt.Fprintln(os.Stderr, "error:", yke.FullError())
	os.Exit(1)
}
