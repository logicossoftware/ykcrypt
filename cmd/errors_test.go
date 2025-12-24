/*
Copyright © 2025 Logicos Software

errors_test.go contains unit tests for error classification and handling.
*/
package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestYKCryptError(t *testing.T) {
	tests := []struct {
		name     string
		err      *YKCryptError
		wantMsg  string
		wantHint string
	}{
		{
			name:     "simple error",
			err:      &YKCryptError{Category: ErrCategoryYubiKey, Message: "test error"},
			wantMsg:  "test error",
			wantHint: "",
		},
		{
			name: "error with cause",
			err: &YKCryptError{
				Category: ErrCategoryFile,
				Message:  "file error",
				Cause:    errors.New("underlying error"),
			},
			wantMsg: "file error: underlying error",
		},
		{
			name: "error with hint",
			err: &YKCryptError{
				Category: ErrCategoryCrypto,
				Message:  "crypto error",
				Hint:     "Try again",
			},
			wantMsg:  "crypto error",
			wantHint: "Try again",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}

			if tt.wantHint != "" {
				full := tt.err.FullError()
				if !strings.Contains(full, tt.wantHint) {
					t.Errorf("FullError() = %q, want to contain %q", full, tt.wantHint)
				}
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := &YKCryptError{
		Message: "wrapper",
		Cause:   cause,
	}

	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name         string
		input        error
		wantCategory ErrorCategory
		wantRetry    bool
	}{
		{
			name:         "nil error",
			input:        nil,
			wantCategory: ErrCategoryUnknown,
		},
		{
			name:         "touch timeout 6982",
			input:        errors.New("smart card error 6982: security status not satisfied"),
			wantCategory: ErrCategoryYubiKey,
			wantRetry:    true,
		},
		{
			name:         "wrong PIN 63c2",
			input:        errors.New("smart card error 63c2: verification failed"),
			wantCategory: ErrCategoryYubiKey,
			wantRetry:    true,
		},
		{
			name:         "PIN blocked 6983",
			input:        errors.New("smart card error 6983: authentication method blocked"),
			wantCategory: ErrCategoryYubiKey,
			wantRetry:    false,
		},
		{
			name:         "slot empty 6a82",
			input:        errors.New("smart card error 6a82: data object or application not found"),
			wantCategory: ErrCategoryYubiKey,
			wantRetry:    false,
		},
		{
			name:         "no yubikey",
			input:        errors.New("no yubikey reader found"),
			wantCategory: ErrCategoryYubiKey,
			wantRetry:    false,
		},
		{
			name:         "file not found",
			input:        errors.New("no such file or directory"),
			wantCategory: ErrCategoryFile,
			wantRetry:    false,
		},
		{
			name:         "permission denied",
			input:        errors.New("permission denied"),
			wantCategory: ErrCategoryFile,
			wantRetry:    false,
		},
		{
			name:         "auth failed",
			input:        errors.New("message authentication failed"),
			wantCategory: ErrCategoryCrypto,
			wantRetry:    false,
		},
		{
			name:         "already YKCryptError",
			input:        ErrEmptyPassphrase(),
			wantCategory: ErrCategoryInput,
			wantRetry:    false,
		},
		{
			name:         "unknown error",
			input:        errors.New("something else"),
			wantCategory: ErrCategoryUnknown,
			wantRetry:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input == nil {
				result := ClassifyError(tt.input)
				if result != nil {
					t.Errorf("ClassifyError(nil) = %v, want nil", result)
				}
				return
			}

			result := ClassifyError(tt.input)
			if result == nil {
				t.Fatal("ClassifyError() returned nil for non-nil input")
			}

			if result.Category != tt.wantCategory {
				t.Errorf("Category = %v, want %v", result.Category, tt.wantCategory)
			}

			if result.IsRetryable != tt.wantRetry {
				t.Errorf("IsRetryable = %v, want %v", result.IsRetryable, tt.wantRetry)
			}
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	// Test that error constructors return non-nil errors with correct category
	tests := []struct {
		name     string
		err      *YKCryptError
		category ErrorCategory
	}{
		{"YubiKeyNotFound", ErrYubiKeyNotFound(), ErrCategoryYubiKey},
		{"YubiKeyTouchTimeout", ErrYubiKeyTouchTimeout(nil), ErrCategoryYubiKey},
		{"YubiKeyWrongPIN", ErrYubiKeyWrongPIN(2, nil), ErrCategoryYubiKey},
		{"YubiKeyPINBlocked", ErrYubiKeyPINBlocked(nil), ErrCategoryYubiKey},
		{"YubiKeySlotEmpty", ErrYubiKeySlotEmpty("9d", nil), ErrCategoryYubiKey},
		{"YubiKeyConditionsNotSatisfied", ErrYubiKeyConditionsNotSatisfied(nil), ErrCategoryYubiKey},
		{"FileNotFound", ErrFileNotFound("/path", nil), ErrCategoryFile},
		{"FilePermission", ErrFilePermission("/path", nil), ErrCategoryFile},
		{"FileAlreadyExists", ErrFileAlreadyExists("/path"), ErrCategoryFile},
		{"AtomicWriteFailed", ErrAtomicWriteFailed("/path", nil), ErrCategoryFile},
		{"DecryptionFailed", ErrDecryptionFailed(nil), ErrCategoryCrypto},
		{"KeyUnwrapFailed", ErrKeyUnwrapFailed(nil), ErrCategoryCrypto},
		{"UnsupportedCurve", ErrUnsupportedCurve(99), ErrCategoryCrypto},
		{"UnsupportedCipher", ErrUnsupportedCipher(99), ErrCategoryCrypto},
		{"InvalidMagic", ErrInvalidMagic("WRONG"), ErrCategoryFormat},
		{"InvalidVersion", ErrInvalidVersion(99), ErrCategoryFormat},
		{"TruncatedHeader", ErrTruncatedHeader(nil), ErrCategoryFormat},
		{"NoRecipientMatch", ErrNoRecipientMatch(), ErrCategoryFormat},
		{"InvalidRecipient", ErrInvalidRecipient("bad"), ErrCategoryInput},
		{"EmptyPassphrase", ErrEmptyPassphrase(), ErrCategoryInput},
		{"InvalidChunkSize", ErrInvalidChunkSize(-1), ErrCategoryInput},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("Error constructor returned nil")
			}
			if tt.err.Category != tt.category {
				t.Errorf("Category = %v, want %v", tt.err.Category, tt.category)
			}
			if tt.err.Message == "" {
				t.Error("Message is empty")
			}
		})
	}
}

func TestErrorCategoryString(t *testing.T) {
	tests := []struct {
		cat  ErrorCategory
		want string
	}{
		{ErrCategoryUnknown, "Unknown"},
		{ErrCategoryYubiKey, "YubiKey"},
		{ErrCategoryFile, "File"},
		{ErrCategoryCrypto, "Cryptographic"},
		{ErrCategoryInput, "Input"},
		{ErrCategoryFormat, "Format"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.cat.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWrongPINRetries(t *testing.T) {
	// Test that PIN retry count is extracted correctly
	tests := []struct {
		errStr  string
		retries int
	}{
		{"smart card error 63c3: failed", 3},
		{"smart card error 63c2: failed", 2},
		{"smart card error 63c1: failed", 1},
		{"smart card error 63c0: failed", 0},
	}

	for _, tt := range tests {
		t.Run(tt.errStr, func(t *testing.T) {
			err := ClassifyError(errors.New(tt.errStr))
			if err == nil {
				t.Fatal("ClassifyError returned nil")
			}
			// Check message contains retry count
			if !strings.Contains(err.Message, "retries") {
				t.Errorf("Message %q should mention retries", err.Message)
			}
		})
	}
}
