package misc

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWritePrivateCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateCredential(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "new")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected mode: %o", info.Mode().Perm())
	}
	if err := WritePrivateCredential(path, func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return errors.New("encoding failed")
	}); err == nil {
		t.Fatal("expected failure")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("credential changed after failure: %v", err)
	}
}

func TestWritePrivateCredentialRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "link")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := WritePrivateCredential(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "changed")
		return err
	}); err == nil {
		t.Fatal("expected symlink rejection")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "original" {
		t.Fatal("symlink target changed")
	}
}
