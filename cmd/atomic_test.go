/*
Copyright © 2025 Logicos Software

atomic_test.go contains unit tests for atomic file operations.
*/
package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriter(t *testing.T) {
	dir := t.TempDir()

	t.Run("basic write and commit", func(t *testing.T) {
		path := filepath.Join(dir, "test1.txt")
		data := []byte("Hello, World!")

		w, err := NewAtomicWriter(path, false)
		if err != nil {
			t.Fatalf("NewAtomicWriter failed: %v", err)
		}

		n, err := w.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Errorf("Write returned %d, want %d", n, len(data))
		}

		if err := w.Commit(); err != nil {
			t.Fatalf("Commit failed: %v", err)
		}

		// Verify file contents
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("File contents = %q, want %q", got, data)
		}

		// Verify temp file is gone
		tempPath := filepath.Join(dir, ".test1.txt.tmp")
		if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
			t.Error("Temp file should not exist after commit")
		}
	})

	t.Run("abort removes temp file", func(t *testing.T) {
		path := filepath.Join(dir, "test2.txt")

		w, err := NewAtomicWriter(path, false)
		if err != nil {
			t.Fatalf("NewAtomicWriter failed: %v", err)
		}

		w.Write([]byte("data"))
		w.Abort()

		// Verify neither file exists
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("Target file should not exist after abort")
		}
		tempPath := filepath.Join(dir, ".test2.txt.tmp")
		if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
			t.Error("Temp file should not exist after abort")
		}
	})

	t.Run("prevents overwrite when not allowed", func(t *testing.T) {
		path := filepath.Join(dir, "test3.txt")

		// Create existing file
		if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		_, err := NewAtomicWriter(path, false)
		if err == nil {
			t.Error("Expected error when file exists and overwrite not allowed")
		}
	})

	t.Run("allows overwrite when allowed", func(t *testing.T) {
		path := filepath.Join(dir, "test4.txt")

		// Create existing file
		if err := os.WriteFile(path, []byte("old data"), 0o600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		w, err := NewAtomicWriter(path, true)
		if err != nil {
			t.Fatalf("NewAtomicWriter failed: %v", err)
		}

		newData := []byte("new data")
		w.Write(newData)
		if err := w.Commit(); err != nil {
			t.Fatalf("Commit failed: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if !bytes.Equal(got, newData) {
			t.Errorf("File contents = %q, want %q", got, newData)
		}
	})

	t.Run("close commits if not aborted", func(t *testing.T) {
		path := filepath.Join(dir, "test5.txt")
		data := []byte("auto commit")

		w, err := NewAtomicWriter(path, false)
		if err != nil {
			t.Fatalf("NewAtomicWriter failed: %v", err)
		}

		w.Write(data)
		if err := w.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("File contents = %q, want %q", got, data)
		}
	})

	t.Run("double commit is safe", func(t *testing.T) {
		path := filepath.Join(dir, "test6.txt")

		w, err := NewAtomicWriter(path, false)
		if err != nil {
			t.Fatalf("NewAtomicWriter failed: %v", err)
		}

		w.Write([]byte("data"))
		if err := w.Commit(); err != nil {
			t.Fatalf("First commit failed: %v", err)
		}
		if err := w.Commit(); err != nil {
			t.Fatalf("Second commit should be no-op: %v", err)
		}
	})

	t.Run("file permissions are restricted", func(t *testing.T) {
		// Skip on Windows as Unix file permissions don't apply
		if os.PathSeparator == '\\' {
			t.Skip("Skipping permission test on Windows")
		}

		path := filepath.Join(dir, "test7.txt")

		w, err := NewAtomicWriter(path, false)
		if err != nil {
			t.Fatalf("NewAtomicWriter failed: %v", err)
		}

		w.Write([]byte("secret"))
		w.Commit()

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}

		// Check file is not world-readable (on Unix-like systems)
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			t.Errorf("File permissions %o allow group/world access", mode)
		}
	})
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	data := []byte("atomic write test")

	if err := WriteFileAtomic(path, data, false); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("File contents = %q, want %q", got, data)
	}
}

func TestCopyFileAtomic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	dst := filepath.Join(dir, "dest.txt")
	data := []byte("copy test data")

	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := CopyFileAtomic(src, dst); err != nil {
		t.Fatalf("CopyFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("File contents = %q, want %q", got, data)
	}
}

func BenchmarkAtomicWrite(b *testing.B) {
	dir := b.TempDir()
	data := make([]byte, 1024*1024) // 1 MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := filepath.Join(dir, "bench.txt")
		w, _ := NewAtomicWriter(path, true)
		w.Write(data)
		w.Commit()
	}
}
