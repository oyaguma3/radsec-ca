package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/ca/catest"
	"github.com/oyaguma3/radsec-ca/internal/certs"
	"github.com/oyaguma3/radsec-ca/internal/db"
)

type testEnv struct {
	url    string
	client *http.Client
	db     *db.DB
	// dial は任意のクライアント証明書でつなぐ（nil なら証明書なし）。
	dial func(cert *tls.Certificate) error
}

func keyPair(t *testing.T, server bool) tls.Certificate {
	t.Helper()
	var c, k []byte
	var err error
	if server {
		c, k, err = certs.SelfSigned("radsec-ca", []string{"127.0.0.1"}, time.Hour)
	} else {
		c, k, err = selfSignedClient()
	}
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// selfSignedClient はクライアント証明書を作る（試験用。サーバー用と同じ作りで足りる）。
func selfSignedClient() ([]byte, []byte, error) {
	return certs.SelfSigned("provisioner", nil, time.Hour)
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	svc, d := catest.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srvCert := keyPair(t, true)
	clientCert := keyPair(t, false)
	clients := map[string]string{certs.Fingerprint(clientCert.Leaf): "provisioner"}
	h := &Handler{Log: log, DB: d, CA: svc, Version: "test", KEKID: "0011223344556677",
		MgmtClient: func(r *http.Request) string { return AdminClientName(r, clients) }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go Serve(t.Context(), ln, ListenOptions{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil },
		AdminClients: clients, Handler: h.Routes(), Log: log})
	pool := x509.NewCertPool()
	pool.AddCert(srvCert.Leaf)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientCert}}}
	addr := ln.Addr().String()
	dial := func(cert *tls.Certificate) error {
		cfg := &tls.Config{RootCAs: pool}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := c.Get("https://" + addr + "/status")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	return &testEnv{url: "https://" + addr, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}, db: d, dial: dial}
}

type resp struct {
	status int
	header http.Header
	body   map[string]any
	raw    []byte
}

func (e *testEnv) do(t *testing.T, method, path string, body any, hdr map[string]string) resp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body, json.Deterministic(true))
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.url+path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	out := resp{status: r.StatusCode, header: r.Header, raw: raw}
	json.Unmarshal(raw, &out.body)
	return out
}

func idem(k string) map[string]string {
	return map[string]string{"Idempotency-Key": k, "X-Operator-Id": "admin@example.com"}
}

func expect(t *testing.T, what string, r resp, status int, cause string) {
	t.Helper()
	if r.status != status || (cause != "" && r.body["cause"] != cause) {
		t.Fatalf("%s: status %d cause %v (want %d %s): %s", what, r.status, r.body["cause"], status, cause, r.raw)
	}
	if status >= 400 && r.header.Get("Content-Type") != "application/problem+json" {
		t.Errorf("%s: Content-Type = %s", what, r.header.Get("Content-Type"))
	}
}

func TestMTLS(t *testing.T) {
	e := newTestEnv(t)
	if err := e.dial(nil); err == nil {
		t.Error("connection without a client certificate was accepted")
	}
	other := keyPair(t, false)
	if err := e.dial(&other); err == nil {
		t.Error("unregistered client certificate was accepted")
	}
	r := e.do(t, "GET", "/status", nil, map[string]string{"X-Trace-ID": "trace-1"})
	if r.status != 200 || r.body["service"] != "radsec-ca" || r.body["kekId"] != "0011223344556677" || r.body["urnPrefix"] != "example" ||
		r.header.Get("X-Trace-ID") != "trace-1" {
		t.Fatalf("status: %d %s %v", r.status, r.raw, r.header)
	}
	cas := r.body["cas"].([]any)
	if len(cas) != 1 || cas[0].(map[string]any)["id"] != "server" || cas[0].(map[string]any)["crl"] == nil {
		t.Errorf("status cas: %v", cas)
	}
}

func TestCAsAndCerts(t *testing.T) {
	e := newTestEnv(t)
	expect(t, "no key", e.do(t, "POST", "/cas", map[string]any{"tenant": "tenant-a"}, nil), 400, ca.CauseValidation)
	r := e.do(t, "POST", "/cas", map[string]any{"tenant": "tenant-a"}, idem("k1"))
	expect(t, "create", r, 201, "")
	if r.body["id"] != "tenant.tenant-a" || !strings.Contains(r.body["certificate"].(string), "BEGIN CERTIFICATE") || r.header.Get("Location") != "/cas/tenant.tenant-a" {
		t.Errorf("create: %s", r.raw)
	}
	// 同じ鍵・同じ本文の再送には前の応答を返す。本文が違えば 409。
	r2 := e.do(t, "POST", "/cas", map[string]any{"tenant": "tenant-a"}, idem("k1"))
	if r2.status != 201 || r2.header.Get("Idempotent-Replayed") != "true" || !bytes.Equal(r2.raw, r.raw) {
		t.Errorf("replay: %d %v", r2.status, r2.header)
	}
	expect(t, "same key, other body", e.do(t, "POST", "/cas", map[string]any{"tenant": "tenant-b"}, idem("k1")), 409, causeIdempotencyConflict)
	expect(t, "exists", e.do(t, "POST", "/cas", map[string]any{"tenant": "tenant-a"}, idem("k2")), 409, ca.CauseCAExists)
	expect(t, "bad slug", e.do(t, "POST", "/cas", map[string]any{"tenant": "A"}, idem("k3")), 400, ca.CauseValidation)
	expect(t, "unknown member", e.do(t, "POST", "/cas", map[string]any{"tenant": "x", "key": "y"}, idem("k4")), 400, ca.CauseValidation)
	expect(t, "get", e.do(t, "GET", "/cas/tenant.tenant-a", nil, nil), 200, "")
	expect(t, "get unknown", e.do(t, "GET", "/cas/tenant.none", nil, nil), 404, ca.CauseCANotFound)
	if r := e.do(t, "GET", "/cas", nil, nil); r.status != 200 || len(r.body["items"].([]any)) != 2 {
		t.Errorf("list cas: %s", r.raw)
	}

	csr := string(catest.CSR(t, catest.Key(t)))
	issue := map[string]any{"profile": "ap-client", "tenant": "tenant-a", "ap": "ap-001", "csr": csr}
	r = e.do(t, "POST", "/certs", issue, idem("i1"))
	expect(t, "issue", r, 201, "")
	serial := r.body["serial"].(string)
	if r.body["cn"] != "tenant-a-ap-001" || r.body["sanUri"] != "urn:example:nas:tenant-a:ap-001" || r.body["status"] != "valid" ||
		r.body["caId"] != "tenant.tenant-a" || !strings.Contains(r.body["caCertificate"].(string), "BEGIN CERTIFICATE") {
		t.Errorf("issue: %s", r.raw)
	}
	// 同じ鍵の再送で 2 枚目はできない。
	if r := e.do(t, "POST", "/certs", issue, idem("i1")); r.body["serial"] != serial {
		t.Errorf("replayed issue created another certificate: %s", r.raw)
	}
	expect(t, "reserved", e.do(t, "POST", "/certs", map[string]any{"profile": "ap-client", "tenant": "tenant-a", "ap": "probe", "csr": csr}, idem("i2")), 422, ca.CauseNameReserved)
	expect(t, "bad csr", e.do(t, "POST", "/certs", map[string]any{"profile": "ap-client", "tenant": "tenant-a", "ap": "ap-2", "csr": "x"}, idem("i3")), 422, ca.CauseCSRInvalid)
	expect(t, "no CA", e.do(t, "POST", "/certs", map[string]any{"profile": "ap-client", "tenant": "tenant-b", "ap": "ap-2", "csr": csr}, idem("i4")), 404, ca.CauseCANotFound)
	r = e.do(t, "POST", "/certs", map[string]any{"profile": "tenant-server", "tenant": "tenant-a", "edge": "edge1", "csr": csr}, idem("i5"))
	expect(t, "server", r, 201, "")
	if len(r.body["sanDns"].([]any)) != 3 {
		t.Errorf("server SAN: %s", r.raw)
	}

	if r := e.do(t, "GET", "/certs?tenant=tenant-a&profile=ap-client", nil, nil); r.status != 200 || len(r.body["items"].([]any)) != 1 {
		t.Errorf("list certs: %s", r.raw)
	}
	if r := e.do(t, "GET", "/certs?limit=1", nil, nil); r.status != 200 || len(r.body["items"].([]any)) != 1 || r.body["next"] == nil {
		t.Errorf("paging: %s", r.raw)
	} else if r2 := e.do(t, "GET", "/certs?limit=1&after="+r.body["next"].(string), nil, nil); len(r2.body["items"].([]any)) != 1 || r2.body["next"] != nil {
		t.Errorf("second page: %s", r2.raw)
	}
	expect(t, "bad status filter", e.do(t, "GET", "/certs?status=bad", nil, nil), 400, ca.CauseValidation)

	expect(t, "revoke without key", e.do(t, "POST", "/certs/"+serial+"/revoke", map[string]any{"reason": "superseded"}, nil), 400, ca.CauseValidation)
	r = e.do(t, "POST", "/certs/"+serial+"/revoke", map[string]any{"reason": "superseded"}, idem("r1"))
	expect(t, "revoke", r, 200, "")
	if r.body["status"] != "revoked" || r.body["revokeReason"] != "superseded" {
		t.Errorf("revoke: %s", r.raw)
	}
	expect(t, "revoke unknown", e.do(t, "POST", "/certs/ffff/revoke", map[string]any{"reason": "superseded"}, idem("r2")), 404, ca.CauseCertNotFound)
	if r := e.do(t, "GET", "/cas/tenant.tenant-a/crl", nil, nil); r.status != 200 || r.body["number"] != float64(2) || !strings.Contains(r.body["crl"].(string), "X509 CRL") {
		t.Errorf("crl: %s", r.raw)
	}

	r = e.do(t, "POST", "/cas/tenant.tenant-a/disable", nil, idem("d1"))
	expect(t, "disable", r, 200, "")
	if r.body["status"] != "disabled" {
		t.Errorf("disable: %s", r.raw)
	}
	expect(t, "issue after disable", e.do(t, "POST", "/certs", map[string]any{"profile": "ap-client", "tenant": "tenant-a", "ap": "ap-3", "csr": csr}, idem("i6")), 409, ca.CauseCADisabled)

	// 監査ログに管理クライアントと操作者が残る。
	es, _ := e.db.ListAudit(t.Context(), 0, 100)
	found := false
	for _, a := range es {
		if a.Action == "cert.issue" && a.MgmtClient == "provisioner" && a.Operator == "admin@example.com" && a.Source == "api" && a.TraceID != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("audit: %+v", es)
	}
}

func TestFallbackAndHeaders(t *testing.T) {
	e := newTestEnv(t)
	expect(t, "unknown path", e.do(t, "GET", "/nosuch", nil, nil), 404, "")
	r := e.do(t, "DELETE", "/cas", nil, nil)
	expect(t, "method", r, 405, "")
	if r.header.Get("Allow") == "" {
		t.Error("no Allow header")
	}
	expect(t, "bad operator", e.do(t, "GET", "/status", nil, map[string]string{"X-Operator-Id": "a b"}), 400, ca.CauseValidation)
	if r := e.do(t, "GET", "/status", nil, map[string]string{"X-Trace-ID": "bad id!"}); len(r.header.Get("X-Trace-ID")) != 32 {
		t.Errorf("trace id was not generated: %q", r.header.Get("X-Trace-ID"))
	}
}
