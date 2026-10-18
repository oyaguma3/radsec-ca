package publish

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/ca/catest"
)

func TestPublish(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	if _, err := svc.CreateTenantCA(ctx, ca.System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&Handler{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d}).Routes())
	defer srv.Close()
	get := func(path, etag string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	resp, body := get("/crl/tenant.tenant-a.pem", "")
	etag := resp.Header.Get("ETag")
	if resp.StatusCode != 200 || etag == "" || resp.Header.Get("Last-Modified") == "" || resp.Header.Get("Cache-Control") != "max-age=60" {
		t.Fatalf("crl: %d %v", resp.StatusCode, resp.Header)
	}
	b, _ := pem.Decode(body)
	crl, err := x509.ParseRevocationList(b.Bytes)
	if err != nil || crl.Number.Int64() != 1 {
		t.Fatalf("crl body: %v %v", crl, err)
	}
	// 変わっていなければ 304 で本文を送らない。
	if resp, body := get("/crl/tenant.tenant-a.pem", etag); resp.StatusCode != 304 || len(body) != 0 {
		t.Errorf("If-None-Match: %d %d bytes", resp.StatusCode, len(body))
	}
	// 失効させると番号が進み、ETag も変わる。
	issued, err := svc.Issue(ctx, ca.System, ca.IssueRequest{Profile: "ap-client", Material: ca.Material{Tenant: "tenant-a", AP: "ap-1"}, CSR: catest.CSR(t, catest.Key(t))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Revoke(ctx, ca.System, issued.Cert.Serial, "superseded"); err != nil {
		t.Fatal(err)
	}
	resp, _ = get("/crl/tenant.tenant-a.pem", etag)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") == etag {
		t.Errorf("after revoke: %d %s", resp.StatusCode, resp.Header.Get("ETag"))
	}
	resp, body = get("/crl/tenant.tenant-a.der", "")
	if c, err := x509.ParseRevocationList(body); resp.StatusCode != 200 || err != nil || c.Number.Int64() != 2 ||
		resp.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Errorf("der: %d %v %v", resp.StatusCode, err, resp.Header)
	}
	resp, body = get("/ca/server.pem", "")
	b, _ = pem.Decode(body)
	if c, err := x509.ParseCertificate(b.Bytes); resp.StatusCode != 200 || err != nil || !c.IsCA {
		t.Errorf("ca: %d %v", resp.StatusCode, err)
	}
	if resp, _ := get("/ca/server.pem", resp.Header.Get("ETag")); resp.StatusCode != 304 {
		t.Errorf("ca If-None-Match: %d", resp.StatusCode)
	}
	for _, p := range []string{"/crl/tenant.none.pem", "/crl/tenant.tenant-a.txt", "/crl/../x.pem", "/ca/bad.pem", "/crl/server"} {
		if resp, _ := get(p, ""); resp.StatusCode != 404 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}
