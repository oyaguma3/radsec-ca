package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

type env struct {
	svc *Service
	db  *db.DB
	sig *signer.Local
}

func newEnv(t *testing.T) *env {
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
	svc := New(Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d, Signer: sig, Org: "Example Org",
		URNPrefix: "example", DNSDomain: "radsec.test", APCertDays: 730, ServerCertDays: 365,
		CRLValidity: 7 * 24 * time.Hour, CRLRefresh: 24 * time.Hour})
	if _, err := svc.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, db: d, sig: sig}
}

// csr は鍵 key の CSR を作る。Subject と SAN には、使われてはならない値を入れる（CA は公開鍵だけを使う）。
func csr(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	evil, _ := url.Parse("urn:example:nas:other:ap-999")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "evil", Organization: []string{"Evil"}}, DNSNames: []string{"evil.example.com"},
		URIs: []*url.URL{evil}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func p256(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func parse(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func cause(err error) string {
	if e, ok := AsError(err); ok {
		return e.Cause
	}
	return ""
}

func TestInitAndCreateCA(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if created, err := e.svc.Init(ctx); err != nil || created {
		t.Errorf("second Init = %v, %v", created, err)
	}
	srv, err := e.db.CA(ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(srv.CertDER)
	if c.Subject.CommonName != "Example Org RadSec server CA" || c.Subject.Organization[0] != "Example Org" || !c.IsCA ||
		!c.MaxPathLenZero || c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(c.SubjectKeyId) == 0 {
		t.Errorf("server CA = %+v", c)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Errorf("server CA is not self-signed: %v", err)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got < 3649*24*time.Hour {
		t.Errorf("CA validity = %v", got)
	}
	// 作ったときに最初の CRL を作る。
	crl, err := e.db.LatestCRL(ctx, "server")
	if err != nil || crl.Number != 1 {
		t.Errorf("first CRL = %+v, %v", crl, err)
	}

	tc, err := e.svc.CreateTenantCA(ctx, System, "tenant-a")
	if err != nil || tc.ID != "tenant.tenant-a" || tc.Kind != db.KindTenantClient || tc.Tenant != "tenant-a" {
		t.Fatalf("CreateTenantCA = %+v, %v", tc, err)
	}
	tcert, _ := x509.ParseCertificate(tc.CertDER)
	if tcert.Subject.CommonName != "tenant-a client CA" {
		t.Errorf("tenant CA CN = %s", tcert.Subject.CommonName)
	}
	if _, err := e.svc.CreateTenantCA(ctx, System, "tenant-a"); cause(err) != CauseCAExists {
		t.Errorf("duplicate CA: %v", err)
	}
	if _, err := e.svc.CreateTenantCA(ctx, System, "Tenant.A"); cause(err) != CauseValidation {
		t.Errorf("bad slug: %v", err)
	}
}

func TestIssueProfiles(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.svc.CreateTenantCA(ctx, System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	tca, _ := e.db.CA(ctx, "tenant.tenant-a")
	tcaCert, _ := x509.ParseCertificate(tca.CertDER)
	srvCA, _ := e.db.CA(ctx, "server")
	srvCert, _ := x509.ParseCertificate(srvCA.CertDER)
	now := time.Now()

	key := p256(t)
	got, err := e.svc.Issue(ctx, Actor{Operator: "op", Source: db.SourceGUI}, IssueRequest{Profile: db.ProfileAPClient,
		Material: Material{Tenant: "tenant-a", AP: "ap-001"}, CSR: csr(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, got.CertPEM)
	if c.Subject.CommonName != "tenant-a-ap-001" || len(c.Subject.Organization) != 0 || len(c.DNSNames) != 0 || len(c.URIs) != 1 ||
		c.URIs[0].String() != "urn:example:nas:tenant-a:ap-001" || !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		c.KeyUsage != x509.KeyUsageDigitalSignature || c.IsCA {
		t.Errorf("ap-client: subject=%s dns=%v uris=%v eku=%v ku=%v", c.Subject, c.DNSNames, c.URIs, c.ExtKeyUsage, c.KeyUsage)
	}
	if err := c.CheckSignatureFrom(tcaCert); err != nil {
		t.Errorf("ap-client is not signed by the tenant CA: %v", err)
	}
	if !bytes.Equal(c.AuthorityKeyId, tcaCert.SubjectKeyId) {
		t.Error("Authority Key Identifier does not match")
	}
	if d := now.Sub(c.NotBefore); d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("NotBefore is %v before now", d)
	}
	if d := c.NotAfter.Sub(now); d < 729*24*time.Hour || d > 731*24*time.Hour {
		t.Errorf("ap-client validity = %v", d)
	}
	if !bytes.Equal(got.CAPEM, CertPEM(tca.CertDER)) {
		t.Error("CAPEM is not the tenant CA")
	}
	rec, err := e.db.Cert(ctx, got.Cert.Serial)
	if err != nil || rec.Profile != db.ProfileAPClient || rec.AP != "ap-001" || rec.PubKeySHA256 != PubKeySHA256(key.Public()) ||
		rec.IssuedBy != "op" || rec.Serial != c.SerialNumber.Text(16) {
		t.Errorf("record = %+v, %v", rec, err)
	}
	if c.SerialNumber.BitLen() < 100 {
		t.Errorf("serial is too short: %d bits", c.SerialNumber.BitLen())
	}

	got, err = e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileProbeClient, Material: Material{Tenant: "tenant-a", Edge: "edge1"}, CSR: csr(t, p256(t))})
	if err != nil {
		t.Fatal(err)
	}
	c = parse(t, got.CertPEM)
	if c.Subject.CommonName != "tenant-a-probe" || c.URIs[0].String() != "urn:example:nas:tenant-a:probe" {
		t.Errorf("probe-client: %s %v", c.Subject, c.URIs)
	}

	got, err = e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileTenantServer, Material: Material{Tenant: "tenant-a", Edge: "edge1"}, CSR: csr(t, p256(t))})
	if err != nil {
		t.Fatal(err)
	}
	c = parse(t, got.CertPEM)
	want := []string{"primary.tenant-a.radsec.test", "secondary.tenant-a.radsec.test", "tertiary.tenant-a.radsec.test"}
	if c.Subject.CommonName != "tenant-a server edge1" || !slices.Equal(c.DNSNames, want) || len(c.URIs) != 0 ||
		!slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("tenant-server: %s %v %v %v", c.Subject, c.DNSNames, c.URIs, c.ExtKeyUsage)
	}
	if err := c.CheckSignatureFrom(srvCert); err != nil {
		t.Errorf("tenant-server is not signed by the server CA: %v", err)
	}
	if d := c.NotAfter.Sub(now); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Errorf("tenant-server validity = %v", d)
	}
}

func TestIssueRejects(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.svc.CreateTenantCA(ctx, System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	good := csr(t, p256(t))
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		req  IssueRequest
		want string
	}{
		{"probe as ap", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "probe"}, CSR: good}, CauseNameReserved},
		{"bad ap", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "AP_1"}, CSR: good}, CauseValidation},
		{"ap with edge", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1", Edge: "e"}, CSR: good}, CauseValidation},
		{"probe without edge", IssueRequest{Profile: db.ProfileProbeClient, Material: Material{Tenant: "tenant-a"}, CSR: good}, CauseValidation},
		{"server with ap", IssueRequest{Profile: db.ProfileTenantServer, Material: Material{Tenant: "tenant-a", AP: "x", Edge: "e"}, CSR: good}, CauseValidation},
		{"unknown profile", IssueRequest{Profile: "root", Material: Material{Tenant: "tenant-a", Edge: "e"}, CSR: good}, CauseValidation},
		{"no tenant CA", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-b", AP: "ap-1"}, CSR: good}, CauseCANotFound},
		{"garbage", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: []byte("x")}, CauseCSRInvalid},
		{"two csrs", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: append(append([]byte{}, good...), good...)}, CauseCSRInvalid},
		{"rsa1024", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: csr(t, rsa1024)}, CauseKeyTypeUnsupported},
		{"ed25519", IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: csr(t, ed)}, CauseKeyTypeUnsupported},
	}
	for _, tc := range cases {
		if _, err := e.svc.Issue(ctx, System, tc.req); cause(err) != tc.want {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.want)
		}
	}
	// CSR の署名を壊す。
	b, _ := pem.Decode(good)
	b.Bytes[len(b.Bytes)-3] ^= 0xff
	if _, err := e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"},
		CSR: pem.EncodeToMemory(b)}); cause(err) != CauseCSRInvalid {
		t.Errorf("bad signature: %v", err)
	}
	// 停止した CA は発行しない。
	if _, err := e.db.DisableCA(ctx, "tenant.tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: good}); cause(err) != CauseCADisabled {
		t.Errorf("disabled CA: %v", err)
	}
}

func TestIssueKeys(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, k := range map[string]crypto.Signer{"rsa2048": rsaKey, "p384": p384} {
		got, err := e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-" + name}, CSR: csr(t, k)})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c := parse(t, got.CertPEM)
		wantKU := x509.KeyUsageDigitalSignature
		if name == "rsa2048" {
			wantKU |= x509.KeyUsageKeyEncipherment
		}
		if c.KeyUsage != wantKU {
			t.Errorf("%s: KeyUsage = %v", name, c.KeyUsage)
		}
	}
}

// 有効期限は CA の期限を超えない（§5.2）。
func TestIssueCappedByCA(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	tca, _ := e.db.CA(ctx, "tenant.tenant-a")
	e.svc.Now = func() time.Time { return tca.NotAfter.Add(-100 * 24 * time.Hour) }
	got, err := e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: csr(t, p256(t))})
	if err != nil {
		t.Fatal(err)
	}
	if c := parse(t, got.CertPEM); !c.NotAfter.Equal(tca.NotAfter.Truncate(time.Second)) && !c.NotAfter.Equal(tca.NotAfter) {
		t.Errorf("NotAfter = %v, CA NotAfter = %v", c.NotAfter, tca.NotAfter)
	}
}

func TestSignerCheckAndRekey(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	if n, err := e.sig.Check(ctx); err != nil || n != 2 {
		t.Fatalf("Check = %d, %v", n, err)
	}
	// 違う KEK では起動しない。
	other, _ := kek.New(bytes.Repeat([]byte{9}, kek.Size))
	if _, err := (&signer.Local{DB: e.db, KEK: other}).Check(ctx); !errors.Is(err, signer.ErrKEKMismatch) {
		t.Errorf("Check(other KEK) = %v", err)
	}
	// KEK を入れ替えると、新しい KEK で起動し、古い KEK では起動しない。
	if n, err := e.sig.Rekey(ctx, other); err != nil || n != 2 {
		t.Fatalf("Rekey = %d, %v", n, err)
	}
	if _, err := (&signer.Local{DB: e.db, KEK: other}).Check(ctx); err != nil {
		t.Errorf("Check(new KEK) = %v", err)
	}
	if _, err := e.sig.Check(ctx); !errors.Is(err, signer.ErrKEKMismatch) {
		t.Errorf("Check(old KEK) = %v", err)
	}
	// 新しい KEK で発行できる。
	e.svc.Signer = &signer.Local{DB: e.db, KEK: other}
	if _, err := e.svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: csr(t, p256(t))}); err != nil {
		t.Errorf("Issue after rekey: %v", err)
	}
}
