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
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/crlfetch"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// New は試験用の Service と DB を作る（組織は Example Org、接頭辞は example、ドメインは radsec.test）。
func New(t testing.TB) (*ca.Service, *db.DB) {
	t.Helper()
	return NewWithMeraki(t, "http://127.0.0.1:1")
}

// NewWithMeraki は Meraki の Dashboard API の入口を指定して New と同じものを作る。
func NewWithMeraki(t testing.TB, merakiBase string) (*ca.Service, *db.DB) {
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
	// 試験の偽の取得先はループバックなので、内部のアドレスへの接続を許す。
	fetcher, err := crlfetch.New(crlfetch.Options{Timeout: 5 * time.Second, AllowPrivate: true, MerakiBase: merakiBase})
	if err != nil {
		t.Fatal(err)
	}
	svc := ca.New(ca.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d, Signer: sig, Org: "Example Org",
		URNPrefix: "example", DNSDomain: "radsec.test", APCertDays: 730, GroupCertDays: 730, ServerCertDays: 365,
		CRLValidity: 7 * 24 * time.Hour, CRLRefresh: 24 * time.Hour, Fetcher: fetcher, BroughtCRLRefresh: time.Hour, Secrets: sig})
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

// VendorCA は業者の CA の代わり（試験用。持ち込みの CA の登録に使う）。
type VendorCA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  []byte
}

// NewVendorCA は自己署名の CA を作る。
func NewVendorCA(t testing.TB, cn string) *VendorCA {
	t.Helper()
	k := Key(t)
	tmpl := vendorTemplate(cn, x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
	return vendorFrom(t, tmpl, tmpl, k, k)
}

// NewIntermediateCA は parent が署名した、自己署名でない CA を作る（Meraki の形）。
func NewIntermediateCA(t testing.TB, parent *VendorCA, cn string) *VendorCA {
	t.Helper()
	return vendorFrom(t, vendorTemplate(cn, x509.KeyUsageCertSign|x509.KeyUsageCRLSign), parent.Cert, Key(t), parent.Key)
}

// NewVendorCAWithUsage は KeyUsage を指定して自己署名の CA を作る。
func NewVendorCAWithUsage(t testing.TB, cn string, usage x509.KeyUsage) *VendorCA {
	t.Helper()
	k := Key(t)
	tmpl := vendorTemplate(cn, usage)
	return vendorFrom(t, tmpl, tmpl, k, k)
}

func vendorTemplate(cn string, usage x509.KeyUsage) *x509.Certificate {
	serial, _ := signer.NewSerial()
	return &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), KeyUsage: usage, BasicConstraintsValid: true, IsCA: true}
}

func vendorFrom(t testing.TB, tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *VendorCA {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &VendorCA{Cert: c, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// CRLOptions は VendorCA.CRL の指定。
type CRLOptions struct {
	// Number は cRLNumber（crypto/x509 は番号なしの CRL を作れない）。
	Number                 int64
	ThisUpdate, NextUpdate time.Time
	// Revoked は失効させるシリアル番号。
	Revoked []*big.Int
	// Delta は差分の CRL の印を付ける。
	Delta bool
}

// CRL は CA の鍵で署名した CRL の DER を作る。
func (v *VendorCA) CRL(t testing.TB, o CRLOptions) []byte {
	t.Helper()
	if o.ThisUpdate.IsZero() {
		o.ThisUpdate = time.Now().Add(-time.Minute)
	}
	if o.NextUpdate.IsZero() {
		o.NextUpdate = time.Now().Add(7 * 24 * time.Hour)
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(o.Number), ThisUpdate: o.ThisUpdate, NextUpdate: o.NextUpdate}
	for _, s := range o.Revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()})
	}
	if o.Delta {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, v.Cert, v.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// CRLPEM は DER の CRL を PEM にする。
func CRLPEM(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}) }
