// Package interop は、本CA が作る証明書と CRL を、ほかの実装が受け付けることを確かめる試験（設計概要 §14、§18 の 2）。
//
//   - openssl: verify -CAfile、verify -crl_check、crl -text（CA_TEST_OPENSSL=1 のときだけ動かす。CI では必ず動かす）
//   - radsec-edge の検証の規則（internal/pki の CheckClientCA・CheckServerCert・CheckClientCert・CheckCRL と同じ確かめ。
//     別のモジュールの internal は使えないので、同じ規則をここに書く。本物の突き合わせは段階 3 の通しで行う）
package interop

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/ca/catest"
	"github.com/oyaguma3/radsec-ca/internal/db"
)

// fixture は、テナントのクライアントCA、AP の証明書 2 枚（1 枚は失効）、probe とサーバーの証明書、CRL を作ってファイルに書く。
type fixture struct {
	dir                          string
	tenantCA, serverCA           *x509.Certificate
	good, revoked, probe, server *x509.Certificate
	crl                          *x509.RevocationList
	files                        map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	svc, d := catest.New(t)
	ctx := t.Context()
	if _, err := svc.CreateTenantCA(ctx, ca.System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: t.TempDir(), files: map[string]string{}}
	issue := func(name, profile string, m ca.Material) *x509.Certificate {
		got, err := svc.Issue(ctx, ca.System, ca.IssueRequest{Profile: profile, Material: m, CSR: catest.CSR(t, catest.Key(t))})
		if err != nil {
			t.Fatal(err)
		}
		f.write(t, name+".pem", got.CertPEM)
		c, _ := x509.ParseCertificate(got.Cert.CertDER)
		return c
	}
	f.good = issue("good", db.ProfileAPClient, ca.Material{Tenant: "tenant-a", AP: "ap-001"})
	f.revoked = issue("revoked", db.ProfileAPClient, ca.Material{Tenant: "tenant-a", AP: "ap-002"})
	f.probe = issue("probe", db.ProfileProbeClient, ca.Material{Tenant: "tenant-a", Edge: "edge1"})
	f.server = issue("tenant-server", db.ProfileTenantServer, ca.Material{Tenant: "tenant-a", Edge: "edge1"})
	if _, err := svc.Revoke(ctx, ca.System, f.revoked.SerialNumber.Text(16), "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	for id, dst := range map[string]**x509.Certificate{"tenant.tenant-a": &f.tenantCA, "server": &f.serverCA} {
		c, _ := d.CA(ctx, id)
		*dst, _ = x509.ParseCertificate(c.CertDER)
		f.write(t, id+".pem", ca.CertPEM(c.CertDER))
	}
	latest, _ := d.LatestCRL(ctx, "tenant.tenant-a")
	f.crl, _ = x509.ParseRevocationList(latest.DER)
	f.write(t, "tenant.crl", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: latest.DER}))
	return f
}

func (f *fixture) write(t *testing.T, name string, data []byte) {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	f.files[name] = p
}

func openssl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "openssl", args...).CombinedOutput()
	return string(out), err
}

func TestOpenSSL(t *testing.T) {
	if os.Getenv("CA_TEST_OPENSSL") != "1" {
		t.Skip("CA_TEST_OPENSSL=1 のときだけ動かす")
	}
	f := newFixture(t)
	p := f.files
	ok := func(name string, args ...string) {
		t.Helper()
		out, err := openssl(t, args...)
		if err != nil || !strings.Contains(out, ": OK") {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
	ok("ap-client", "verify", "-purpose", "sslclient", "-CAfile", p["tenant.tenant-a.pem"], p["good.pem"])
	ok("probe-client", "verify", "-purpose", "sslclient", "-CAfile", p["tenant.tenant-a.pem"], p["probe.pem"])
	ok("tenant-server", "verify", "-purpose", "sslserver", "-CAfile", p["server.pem"], p["tenant-server.pem"])
	ok("crl_check good", "verify", "-crl_check", "-purpose", "sslclient", "-CAfile", p["tenant.tenant-a.pem"], "-CRLfile", p["tenant.crl"], p["good.pem"])
	// 失効させた証明書は CRL で拒否される。
	out, err := openssl(t, "verify", "-crl_check", "-CAfile", p["tenant.tenant-a.pem"], "-CRLfile", p["tenant.crl"], p["revoked.pem"])
	if err == nil || !strings.Contains(out, "certificate revoked") {
		t.Errorf("revoked certificate passed: %v\n%s", err, out)
	}
	// テナントのクライアントCA の証明書は、サーバーCA では通らない（テナントの分離。エッジの設計概要 §9.1）。
	if out, err := openssl(t, "verify", "-CAfile", p["server.pem"], p["good.pem"]); err == nil {
		t.Errorf("AP certificate passed with the server CA:\n%s", out)
	}
	out, err = openssl(t, "crl", "-in", p["tenant.crl"], "-noout", "-text")
	if err != nil {
		t.Fatalf("crl -text: %v\n%s", err, out)
	}
	serial := strings.ToUpper(f.revoked.SerialNumber.Text(16))
	for _, want := range []string{"X509v3 CRL Number", "Next Update", "Key Compromise", "X509v3 Authority Key Identifier"} {
		if !strings.Contains(out, want) {
			t.Errorf("crl -text does not contain %q:\n%s", want, out)
		}
	}
	if !strings.Contains(strings.ReplaceAll(out, ":", ""), serial) && !strings.Contains(out, serial) {
		t.Errorf("crl -text does not list the revoked serial %s:\n%s", serial, out)
	}
	if out, err := openssl(t, "x509", "-in", p["tenant.tenant-a.pem"], "-noout", "-text"); err != nil ||
		!strings.Contains(out, "CA:TRUE, pathlen:0") || !strings.Contains(out, "Certificate Sign, CRL Sign") {
		t.Errorf("tenant CA: %v\n%s", err, out)
	}
}

// TestEdgeRules は、radsec-edge が取り込むときの確かめ（internal/pki と同じ規則）を通ることを確かめる。
func TestEdgeRules(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	// CheckClientCA: 自己署名の CA で、keyCertSign があり、期限の中。
	if !f.tenantCA.IsCA || !f.tenantCA.BasicConstraintsValid || f.tenantCA.KeyUsage&x509.KeyUsageCertSign == 0 ||
		f.tenantCA.CheckSignatureFrom(f.tenantCA) != nil || !now.Before(f.tenantCA.NotAfter) {
		t.Error("tenant CA does not pass CheckClientCA")
	}
	// CheckServerCert: serverAuth と、3 つのスロットの名前。
	if !slices.Contains(f.server.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || f.server.IsCA {
		t.Error("server certificate has no serverAuth")
	}
	for _, s := range []string{"primary", "secondary", "tertiary"} {
		if !slices.Contains(f.server.DNSNames, s+".tenant-a.radsec.test") {
			t.Errorf("server certificate has no %s", s)
		}
	}
	// CheckClientCert: テナントのクライアントCA の発行、clientAuth、SAN の URI。
	for c, uri := range map[*x509.Certificate]string{f.good: "urn:example:nas:tenant-a:ap-001", f.probe: "urn:example:nas:tenant-a:probe"} {
		if c.CheckSignatureFrom(f.tenantCA) != nil || !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
			len(c.URIs) != 1 || c.URIs[0].String() != uri {
			t.Errorf("client certificate %s does not pass CheckClientCert", uri)
		}
	}
	// CheckCRL: クライアントCA の署名、番号、nextUpdate が未来。
	if f.crl.CheckSignatureFrom(f.tenantCA) != nil || f.crl.Number == nil || f.crl.Number.Int64() != 2 || !now.Before(f.crl.NextUpdate) {
		t.Error("CRL does not pass CheckCRL")
	}
}

// 持ち込みの CA（自己署名でない中間 CA）の CRL を openssl が受け付け、グループの証明書が URN の形で検証できることを確かめる。
func TestOpensslBroughtAndGroup(t *testing.T) {
	if os.Getenv("CA_TEST_OPENSSL") == "" {
		t.Skip("set CA_TEST_OPENSSL=1 to run the openssl tests")
	}
	svc, d := catest.New(t)
	ctx := t.Context()
	root := catest.NewVendorCA(t, "vendor root")
	v := catest.NewIntermediateCA(t, root, "vendor org CA")
	c, err := svc.RegisterBrought(ctx, ca.System, ca.BroughtRequest{Tenant: "tenant-a", Name: "v", CertPEM: v.PEM, TenantOnlyConfirmed: true,
		CRL: ca.CRLSource{Source: db.CRLSourceUpload, PEM: catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 3}))}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	latest, err := d.LatestCRL(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write("v.pem", ca.CertPEM(c.CertDER))
	crlFile := write("v.crl", catest.CRLPEM(latest.DER))
	if out, err := exec.Command("openssl", "crl", "-in", crlFile, "-CAfile", caFile, "-noout").CombinedOutput(); err != nil || !strings.Contains(string(out), "verify OK") {
		t.Errorf("openssl crl -CAfile: %v\n%s", err, out)
	}
	if _, err := svc.CreateTenantCA(ctx, ca.System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Issue(ctx, ca.System, ca.IssueRequest{Profile: db.ProfileGroupClient, Material: ca.Material{Tenant: "tenant-a", Group: "unifi"}, CSR: catest.CSR(t, catest.Key(t))})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("openssl", "verify", "-CAfile", write("t.pem", got.CAPEM), write("g.pem", got.CertPEM)).CombinedOutput(); err != nil {
		t.Errorf("openssl verify: %v\n%s", err, out)
	}
	text, err := exec.Command("openssl", "x509", "-in", filepath.Join(dir, "g.pem"), "-noout", "-ext", "subjectAltName").CombinedOutput()
	if err != nil || !strings.Contains(string(text), "URI:urn:example:grp:tenant-a:unifi") {
		t.Errorf("SAN: %v\n%s", err, text)
	}
}
