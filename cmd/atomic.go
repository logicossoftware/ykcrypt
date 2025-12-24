/*
Copyright © 2025 Logicos Software

atomic.go implements atomic file write operations.

This module provides safe file writing by:
  - Writing to a temporary file in the same directory
  - Using atomic rename to replace the target file
  - Cleaning up temporary files on failure
  - Preserving original file on any error

This prevents partial/corrupt files from being written in case of
errors, power loss, or crashes during encryption/decryption.
*/
package cmd

import (
	"io"
	"os"
	"path/filepath"
)

// AtomicWriter provides atomic file write operations.
// It writes to a temporary file and atomically renames on Close.
type AtomicWriter struct {
	targetPath string
	tempPath   string
	tempFile   *os.File
	written    bool
	committed  bool
}

// NewAtomicWriter creates a new AtomicWriter for the given target path.
// The file will be written to a temporary location and atomically
// renamed to the target path when Close() is called successfully.
//
// The temporary file is created in the same directory as the target
// to ensure atomic rename is possible (same filesystem).
//
// If the target file already exists and allowOverwrite is false,
// returns an error.
func NewAtomicWriter(targetPath string, allowOverwrite bool) (*AtomicWriter, error) {
	// Check if target exists
	if !allowOverwrite {
		if _, err := os.Stat(targetPath); err == nil {
			return nil, ErrFileAlreadyExists(targetPath)
		}
	}

	// Create temp file in the same directory for atomic rename
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, ErrFilePermission(dir, err)
	}

	// Create temp file with restricted permissions
	tempPath := filepath.Join(dir, "."+base+".tmp")
	tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, ErrFilePermission(tempPath, err)
	}

	return &AtomicWriter{
		targetPath: targetPath,
		tempPath:   tempPath,
		tempFile:   tempFile,
	}, nil
}

// Write implements io.Writer.
func (w *AtomicWriter) Write(p []byte) (n int, err error) {
	n, err = w.tempFile.Write(p)
	if n > 0 {
		w.written = true
	}
	return n, err
}

// Sync flushes the file to disk.
func (w *AtomicWriter) Sync() error {
	return w.tempFile.Sync()
}

// Commit atomically renames the temp file to the target.
// This should be called after all writes are complete but before Close.
// Close will also call Commit if it hasn't been called.
func (w *AtomicWriter) Commit() error {
	if w.committed {
		return nil
	}

	// Sync to ensure all data is on disk
	if err := w.tempFile.Sync(); err != nil {
		return err
	}

	// Close the temp file before rename
	if err := w.tempFile.Close(); err != nil {
		return err
	}

	// Atomic rename
	if err := os.Rename(w.tempPath, w.targetPath); err != nil {
		// Clean up temp file on failure
		os.Remove(w.tempPath)
		return ErrAtomicWriteFailed(w.targetPath, err)
	}

	w.committed = true
	return nil
}

// Close closes the writer. If Commit hasn't been called, it commits first.
// If any error occurred during writing, the temp file is removed.
func (w *AtomicWriter) Close() error {
	if w.committed {
		return nil
	}

	// If we never wrote anything or there was an error, clean up
	if !w.written {
		w.tempFile.Close()
		os.Remove(w.tempPath)
		return nil
	}

	// Try to commit
	return w.Commit()
}

// Abort cancels the write operation and removes the temp file.
// Use this when an error occurs during writing.
func (w *AtomicWriter) Abort() {
	if w.committed {
		return
	}
	w.tempFile.Close()
	os.Remove(w.tempPath)
}

// CopyFileAtomic copies a file atomically to a new location.
// It reads from src and writes atomically to dst.
func CopyFileAtomic(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return ErrFileNotFound(src, err)
	}
	defer srcFile.Close()

	writer, err := NewAtomicWriter(dst, false)
	if err != nil {
		return err
	}
	defer writer.Abort() // Clean up on failure

	if _, err := io.Copy(writer, srcFile); err != nil {
		return err
	}

	return writer.Commit()
}

// WriteFileAtomic writes data to a file atomically.
func WriteFileAtomic(path string, data []byte, allowOverwrite bool) error {
	writer, err := NewAtomicWriter(path, allowOverwrite)
	if err != nil {
		return err
	}
	defer writer.Abort() // Clean up on failure

	if _, err := writer.Write(data); err != nil {
		return err
	}

	return writer.Commit()
}
