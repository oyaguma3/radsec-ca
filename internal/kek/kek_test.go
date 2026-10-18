package kek

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kek")
	k1, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode())
	}
	if _, err := Generate(p); err == nil {
		t.Error("Generate overwrote an existing file")
	}
	k2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if k1.ID() != k2.ID() || len(k1.ID()) != 16 {
		t.Errorf("IDs = %s, %s", k1.ID(), k2.ID())
	}
	for _, bad := range []string{"", "zz", "00", string(bytes.Repeat([]byte("ab"), 31))} {
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("Load(%q) = nil", bad)
		}
	}
}

func TestSealOpen(t *testing.T) {
	k, _ := New(bytes.Repeat([]byte{1}, Size))
	other, _ := New(bytes.Repeat([]byte{2}, Size))
	ct, nonce, err := k.Seal([]byte("secret key"), "tenant.a")
	if err != nil {
		t.Fatal(err)
	}
	p, err := k.Open(ct, nonce, "tenant.a")
	if err != nil || string(p) != "secret key" {
		t.Fatalf("Open = %q, %v", p, err)
	}
	// 違う KEK、AAD の違う行（別の CA の行に移した暗号文）、壊れた暗号文は復号できない。
	if _, err := other.Open(ct, nonce, "tenant.a"); err == nil {
		t.Error("other KEK decrypted")
	}
	if _, err := k.Open(ct, nonce, "tenant.b"); err == nil {
		t.Error("other AAD decrypted")
	}
	ct[0] ^= 1
	if _, err := k.Open(ct, nonce, "tenant.a"); err == nil {
		t.Error("tampered ciphertext decrypted")
	}
	if _, err := New([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}
