// Package kek は、CA の秘密鍵を暗号化する鍵（KEK）を扱う（設計概要 §6.1）。
//
// KEK は 32 バイトの乱数で、ファイル（Docker の secrets）で渡す。ファイルには 16 進の 64 文字で書く（前後の空白は無視する）。
// CA の鍵は AES-256-GCM で暗号化し、nonce は 12 バイトの乱数、AAD は CA の ID にする（暗号文を別の CA の行に移しても
// 復号できない）。DB には KEK の識別子（SHA-256 の先頭 8 バイトの 16 進）だけを持つ。
package kek

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Size は KEK の長さ（バイト）。
const Size = 32

// KEK は暗号化の鍵。
type KEK struct {
	aead cipher.AEAD
	id   string
}

// ID は KEK の識別子。
func (k *KEK) ID() string { return k.id }

// New は 32 バイトの鍵から KEK を作る。
func New(key []byte) (*KEK, error) {
	if len(key) != Size {
		return nil, fmt.Errorf("kek: the key must be %d bytes (got %d)", Size, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	return &KEK{aead: aead, id: hex.EncodeToString(sum[:8])}, nil
}

// Load は KEK のファイルを読む。
func Load(path string) (*KEK, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kek: read %s: %w", path, err)
	}
	key, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(key) != Size {
		return nil, fmt.Errorf("kek: %s must contain %d random bytes in hexadecimal (%d characters). Create one with radsec-ca gen-kek", path, Size, Size*2)
	}
	return New(key)
}

// Generate は新しい KEK のファイルを作る（16 進、権限 0600）。ファイルがあれば上書きしない。
func Generate(path string) (*KEK, error) {
	key := make([]byte, Size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("kek: %s already exists (it is not overwritten)", path)
	}
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(f, hex.EncodeToString(key)); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return New(key)
}

// Seal は plain を暗号化し、暗号文と nonce を返す。aad は CA の ID。
func (k *KEK) Seal(plain []byte, aad string) (ct, nonce []byte, err error) {
	nonce = make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return k.aead.Seal(nil, nonce, plain, []byte(aad)), nonce, nil
}

// Open は暗号文を復号する。KEK・nonce・aad のどれかが違えば失敗する。
func (k *KEK) Open(ct, nonce []byte, aad string) ([]byte, error) {
	if len(nonce) != k.aead.NonceSize() {
		return nil, errors.New("kek: invalid nonce")
	}
	p, err := k.aead.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, errors.New("kek: cannot decrypt (wrong KEK or a record moved to another CA)")
	}
	return p, nil
}
