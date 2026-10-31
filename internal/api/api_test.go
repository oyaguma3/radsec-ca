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
	"net/http/httptest"
	"os"
	"path/filepath"
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
	pins := NewPins(Clients{certs.Fingerprint(clientCert.Leaf): "provisioner"})
	h := &Handler{Log: log, DB: d, CA: svc, Version: "test", KEKID: "0011223344556677", MgmtClient: pins.NameFromRequest}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go Serve(t.Context(), ln, ListenOptions{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil },
		Pins: pins, Handler: h.Routes(), Log: log})
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

// call は JSON の要求を送り、ステータスと本文を返す。
func (e *testEnv) call(t *testing.T, method, path, key string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.url+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	req.Header.Set("X-Operator-Id", "d@example.com")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	if len(b) > 0 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s %s: %s: %v", method, path, b, err)
		}
	}
	return resp.StatusCode, out
}

func TestBroughtAPI(t *testing.T) {
	e := newTestEnv(t)
	v := catest.NewVendorCA(t, "vendor")
	body := v.CRL(t, catest.CRLOptions{Number: 3})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()

	// 種類を付けないと持ち込みの項目は受けない。
	s, out := e.call(t, "POST", "/cas", "k0", map[string]any{"tenant": "tenant-a", "name": "v"})
	if s != 400 {
		t.Errorf("no kind: %d %v", s, out)
	}
	s, out = e.call(t, "POST", "/cas", "k1", map[string]any{"tenant": "tenant-a", "kind": "brought", "name": "v", "certPem": string(v.PEM),
		"crl": map[string]any{"source": "url", "url": srv.URL}})
	if s != 422 || out["cause"] != ca.CauseTenantOnlyNotConfirmed {
		t.Errorf("not confirmed: %d %v", s, out)
	}
	s, out = e.call(t, "POST", "/cas", "k2", map[string]any{"tenant": "tenant-a", "kind": "brought", "name": "v", "certPem": string(v.PEM),
		"crl": map[string]any{"source": "url", "url": srv.URL}, "tenantOnlyConfirmed": true})
	if s != 201 {
		t.Fatalf("register: %d %v", s, out)
	}
	if out["id"] != "brought.tenant-a.v" || out["kind"] != "tenant-brought" || out["selfSigned"] != true || out["hasCrl"] != true ||
		out["crlSource"] != "url" || out["tenantOnlyConfirmedBy"] != "d@example.com" || out["fingerprint"] == "" {
		t.Errorf("registered: %v", out)
	}
	if crl, _ := out["crl"].(map[string]any); crl["extNumber"] != "3" {
		t.Errorf("crl: %v", out["crl"])
	}
	// 同じ CA を別のテナントに。
	s, out = e.call(t, "POST", "/cas", "k3", map[string]any{"tenant": "tenant-b", "kind": "brought", "name": "v", "certPem": string(v.PEM),
		"crl": map[string]any{"source": "url", "url": srv.URL}, "tenantOnlyConfirmed": true})
	if s != 409 || out["cause"] != ca.CauseFingerprintInUse {
		t.Errorf("duplicate: %d %v", s, out)
	}
	// 取り直し。キーは必須。
	s, _ = e.call(t, "POST", "/cas/brought.tenant-a.v/crl:refresh", "", nil)
	if s != 400 {
		t.Errorf("refresh without key: %d", s)
	}
	s, out = e.call(t, "POST", "/cas/brought.tenant-a.v/crl:refresh", "k4", nil)
	if s != 200 {
		t.Errorf("refresh: %d %v", s, out)
	}
	// テナントで絞る。
	if s, out = e.call(t, "GET", "/cas?tenant=tenant-a", "", nil); s != 200 || len(out["items"].([]any)) != 1 {
		t.Errorf("list: %d %v", s, out)
	}
	if s, out = e.call(t, "GET", "/cas?tenant=Bad", "", nil); s != 400 {
		t.Errorf("list bad: %d %v", s, out)
	}
	// 取得先を none に変える。CRL は読めなくなる。
	s, out = e.call(t, "PUT", "/cas/brought.tenant-a.v/crl-source", "k5", map[string]any{"crl": map[string]any{"source": "none"}})
	if s != 422 || out["cause"] != ca.CauseNoCRLNotAccepted {
		t.Errorf("none: %d %v", s, out)
	}
	s, out = e.call(t, "PUT", "/cas/brought.tenant-a.v/crl-source", "k6", map[string]any{"crl": map[string]any{"source": "none"}, "noCrlAccepted": true})
	if s != 200 || out["hasCrl"] != false || out["crl"] != nil {
		t.Errorf("none accepted: %d %v", s, out)
	}
	if s, out = e.call(t, "GET", "/cas/brought.tenant-a.v/crl", "", nil); s != 404 || out["cause"] != ca.CauseCRLNotFound {
		t.Errorf("crl of none: %d %v", s, out)
	}
	// アップロードに替えて、CRL を置く。
	s, out = e.call(t, "PUT", "/cas/brought.tenant-a.v/crl-source", "k7", map[string]any{"crl": map[string]any{"source": "upload", "pem": string(catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 4})))}})
	if s != 200 || out["crlSource"] != "upload" {
		t.Fatalf("to upload: %d %v", s, out)
	}
	s, out = e.call(t, "PUT", "/cas/brought.tenant-a.v/crl", "k8", map[string]any{"pem": string(catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 5})))})
	if s != 200 {
		t.Errorf("upload: %d %v", s, out)
	}
	s, out = e.call(t, "GET", "/cas/brought.tenant-a.v/crl", "", nil)
	if s != 200 || out["extNumber"] != "5" {
		t.Errorf("crl: %d %v", s, out)
	}
	s, out = e.call(t, "PUT", "/cas/brought.tenant-a.v/crl", "k9", map[string]any{"pem": string(catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 1})))})
	if s != 422 || out["cause"] != ca.CauseCRLInvalid {
		t.Errorf("older CRL: %d %v", s, out)
	}
	// 止める。
	if s, out = e.call(t, "POST", "/cas/brought.tenant-a.v/disable", "k10", nil); s != 200 || out["status"] != "disabled" {
		t.Errorf("disable: %d %v", s, out)
	}
	if s, out = e.call(t, "PUT", "/cas/brought.tenant-a.v/crl", "k11", map[string]any{"pem": "x"}); s != 409 || out["cause"] != ca.CauseCADisabled {
		t.Errorf("upload to disabled: %d %v", s, out)
	}
	// 発行した CA には口がない。
	if s, _ = e.call(t, "POST", "/cas", "k12", map[string]any{"tenant": "tenant-a"}); s != 201 {
		t.Errorf("create: %d", s)
	}
	if s, out = e.call(t, "POST", "/cas/tenant.tenant-a/crl:refresh", "k13", nil); s != 400 {
		t.Errorf("refresh issued: %d %v", s, out)
	}
	// グループの証明書。
	s, out = e.call(t, "POST", "/certs", "k14", map[string]any{"profile": "group-client", "tenant": "tenant-a", "group": "unifi", "csr": string(catest.CSR(t, catest.Key(t)))})
	if s != 201 || out["group"] != "unifi" || out["sanUri"] != "urn:example:grp:tenant-a:unifi" {
		t.Errorf("group: %d %v", s, out)
	}
	if s, out = e.call(t, "GET", "/certs?group=unifi&profile=group-client", "", nil); s != 200 || len(out["items"].([]any)) != 1 {
		t.Errorf("list group: %d %v", s, out)
	}
	// 大きな本文も受ける（CRL のアップロード。1 MiB まで）。
	if s, out = e.call(t, "POST", "/cas", "k15", map[string]any{"tenant": strings.Repeat("a", 32), "certPem": strings.Repeat("x", 100<<10)}); s != 400 || out["detail"] == "request body is too large or could not be read" {
		t.Errorf("large: %d %v", s, out)
	}
}

func TestPinsReload(t *testing.T) {
	fpA, fpB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	file := filepath.Join(t.TempDir(), "admin-clients")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadPins(file); err == nil {
		t.Error("missing file accepted")
	}
	write("# コメント\nprovisioner=" + fpA + "\n")
	p, err := LoadPins(file)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := p.lookup(fpA); !ok || n != "provisioner" {
		t.Errorf("lookup: %s %v", n, ok)
	}
	// 同じ識別名に新旧の 2 つ。コロン区切りと大文字も受ける。
	write("provisioner=" + fpA + "\nprovisioner=" + strings.ToUpper(strings.Repeat("BB:", 31)+"BB") + "\n")
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.lookup(fpB); !ok || p.Fingerprints() != 2 || len(p.Names()) != 1 {
		t.Errorf("after reload: %d %v", p.Fingerprints(), p.Names())
	}
	// 読み直せないときは前のまま。
	for _, bad := range []string{"", "# なし\n", "provisioner", "p=short", "bad name=" + fpA, "a=" + fpA + "\nb=" + fpA} {
		write(bad)
		if err := p.Reload(); err == nil {
			t.Errorf("Reload(%q) = nil", bad)
		}
		if _, ok := p.lookup(fpB); !ok {
			t.Errorf("Reload(%q) dropped the pins", bad)
		}
	}
}
