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
	"github.com/oyaguma3/radsec-ca/internal/db"
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

func TestBroughtCRL(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	root := catest.NewVendorCA(t, "root")
	v := catest.NewIntermediateCA(t, root, "vendor")
	c, err := svc.RegisterBrought(ctx, ca.System, ca.BroughtRequest{Tenant: "tenant-a", Name: "v", CertPEM: v.PEM, TenantOnlyConfirmed: true,
		CRL: ca.CRLSource{Source: db.CRLSourceUpload, PEM: catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 9}))}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d}
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()
	get := func(path string, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if len(hdr) == 2 {
			req.Header.Set(hdr[0], hdr[1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := get("/crl/" + c.ID + ".pem")
	block, _ := pem.Decode(body)
	if resp.StatusCode != 200 || block == nil {
		t.Fatalf("crl: %d %s", resp.StatusCode, body)
	}
	// 署名し直さず、受け取ったものをそのまま配る。
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := rl.CheckSignatureFrom(v.Cert); err != nil {
		t.Errorf("signature: %v", err)
	}
	etag := resp.Header.Get("ETag")
	if r, _ := get("/crl/"+c.ID+".pem", "If-None-Match", etag); r.StatusCode != 304 {
		t.Errorf("If-None-Match: %d", r.StatusCode)
	}
	if err := svc.UploadCRL(ctx, ca.System, c.ID, v.CRL(t, catest.CRLOptions{Number: 10})); err != nil {
		t.Fatal(err)
	}
	if r, _ := get("/crl/"+c.ID+".pem", "If-None-Match", etag); r.StatusCode != 200 {
		t.Errorf("after update: %d", r.StatusCode)
	}
	if r, _ := get("/crl/" + c.ID + ".der"); r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Errorf("der: %d", r.StatusCode)
	}
	if r, b := get("/ca/" + c.ID + ".pem"); r.StatusCode != 200 || string(b) != string(v.PEM) {
		t.Errorf("ca: %d", r.StatusCode)
	}
	// 取得先が none なら配らない（CA の証明書は配る）。
	if _, err := svc.ChangeCRLSource(ctx, ca.System, c.ID, ca.CRLSource{Source: db.CRLSourceNone}, true); err != nil {
		t.Fatal(err)
	}
	if r, _ := get("/crl/" + c.ID + ".pem"); r.StatusCode != 404 {
		t.Errorf("crl of none: %d", r.StatusCode)
	}
	if r, _ := get("/ca/" + c.ID + ".pem"); r.StatusCode != 200 {
		t.Errorf("ca of none: %d", r.StatusCode)
	}
	if r, _ := get("/crl/brought.tenant-a.pem"); r.StatusCode != 404 {
		t.Errorf("bad id: %d", r.StatusCode)
	}
}
