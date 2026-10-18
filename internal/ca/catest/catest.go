// Package catest は、試験で本CA を組み立てる部品（一時的な SQLite、決まった KEK、サーバーCA を作った Service）。
package catest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// New は試験用の Service と DB を作る（組織は Example Org、接頭辞は example、ドメインは radsec.test）。
func New(t testing.TB) (*ca.Service, *db.DB) {
	t.Helper()
	d, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "ca.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	k, _ := kek.New(bytes.Repeat([]byte{7}, kek.Size))
	sig := &signer.Local{DB: d, KEK: k}
	if _, err := sig.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	svc := ca.New(ca.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d, Signer: sig, Org: "Example Org",
		URNPrefix: "example", DNSDomain: "radsec.test", APCertDays: 730, ServerCertDays: 365,
		CRLValidity: 7 * 24 * time.Hour, CRLRefresh: 24 * time.Hour})
	if _, err := svc.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	return svc, d
}

// Key は ECDSA P-256 の鍵を作る。
func Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// CSR は鍵 key の CSR（PEM）を作る。
func CSR(t testing.TB, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
