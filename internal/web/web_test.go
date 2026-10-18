package web

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-ca/internal/access"
	"github.com/oyaguma3/radsec-ca/internal/auth"
	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/ca/catest"
	"github.com/oyaguma3/radsec-ca/internal/db"
)

type testEnv struct {
	srv *httptest.Server
	db  *db.DB
	svc *ca.Service
}

func newTestEnv(t *testing.T, ident auth.Identifier, apiEnabled bool) *testEnv {
	t.Helper()
	svc, d := catest.New(t)
	if _, err := d.EnsureInitialAdmin(t.Context(), "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	h, err := New(Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", KEKID: "0011223344556677", DB: d, CA: svc,
		Identifier: ident, InitialAdmin: "admin@example.com", APIEnabled: apiEnabled})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, db: d, svc: svc}
}

var client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *testEnv) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := client.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *testEnv) post(t *testing.T, path string, form url.Values) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func must(t *testing.T, what string, status int, body string, want int, text string) {
	t.Helper()
	if status != want || !strings.Contains(body, text) {
		t.Fatalf("%s: status %d (want %d), body does not contain %q:\n%s", what, status, want, text, body)
	}
}

var certPattern = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)

func TestAdminFlow(t *testing.T) {
	e := newTestEnv(t, auth.Dev("admin@example.com"), false)
	s, body := e.get(t, "/")
	must(t, "home", s, body, 200, "0011223344556677")
	if !strings.Contains(body, "テナントのクライアントCA の作成") || !strings.Contains(body, `href="/sign"`) {
		t.Error("admin controls are not shown")
	}
	s, body, _ = e.post(t, "/cas", url.Values{"tenant": {"Bad_Name"}})
	must(t, "bad tenant", s, body, 422, "テナントの名前は")
	s, _, hdr := e.post(t, "/cas", url.Values{"tenant": {"tenant-a"}})
	if s != 303 || hdr.Get("Location") != "/cas/tenant.tenant-a" {
		t.Fatalf("create CA: %d %v", s, hdr)
	}
	s, body = e.get(t, "/cas/tenant.tenant-a")
	must(t, "ca detail", s, body, 200, "tenant-a client CA")
	s, body = e.get(t, "/cas/tenant.tenant-a/ca.pem")
	must(t, "ca download", s, body, 200, "BEGIN CERTIFICATE")
	s, body = e.get(t, "/cas/tenant.tenant-a/crls/1")
	must(t, "crl download", s, body, 200, "BEGIN X509 CRL")

	// 署名（単独モード）。
	csr := string(catest.CSR(t, catest.Key(t)))
	s, body, _ = e.post(t, "/sign", url.Values{"profile": {"ap-client"}, "tenant": {"tenant-a"}, "ap": {"probe"}, "csr": {csr}})
	must(t, "reserved", s, body, 422, "予約")
	s, body, _ = e.post(t, "/sign", url.Values{"profile": {"ap-client"}, "tenant": {"tenant-a"}, "ap": {"ap-001"}, "csr": {csr}})
	must(t, "sign", s, body, 200, "発行しました")
	if len(certPattern.FindAllString(html.UnescapeString(body), -1)) != 2 {
		t.Errorf("sign result does not show the certificate and the CA certificate:\n%s", body)
	}
	s, body, _ = e.post(t, "/sign", url.Values{"profile": {"tenant-server"}, "tenant": {"tenant-a"}, "edge": {"edge1"}, "csr": {csr}})
	must(t, "sign server", s, body, 200, "tenant-a server edge1")

	page, _ := e.db.Certs(t.Context(), db.CertFilter{Profile: db.ProfileAPClient})
	serial := page.Certs[0].Serial
	s, body = e.get(t, "/certs?tenant=tenant-a&status=valid")
	must(t, "list", s, body, 200, "tenant-a-ap-001")
	s, body = e.get(t, "/certs/"+serial)
	must(t, "cert", s, body, 200, "urn:example:nas:tenant-a:ap-001")
	s, body = e.get(t, "/certs/"+serial+"/cert.pem")
	must(t, "cert download", s, body, 200, "BEGIN CERTIFICATE")
	s, body, _ = e.post(t, "/certs/"+serial+"/revoke", url.Values{"reason": {"certificateHold"}})
	must(t, "bad reason", s, body, 422, "理由は")
	s, body, _ = e.post(t, "/certs/"+serial+"/revoke", url.Values{"reason": {"keyCompromise"}})
	must(t, "revoke", s, body, 200, "失効させ")
	s, body = e.get(t, "/certs?status=revoked")
	must(t, "revoked list", s, body, 200, "tenant-a-ap-001")

	s, body, _ = e.post(t, "/cas/tenant.tenant-a/disable", nil)
	must(t, "disable", s, body, 200, "CA を停止し")

	// 利用者。
	s, body, _ = e.post(t, "/users", url.Values{"email": {"Viewer@Example.com"}, "role": {"viewer"}})
	must(t, "add user", s, body, 200, "viewer@example.com を追加しました")
	s, body, _ = e.post(t, "/users", url.Values{"email": {"viewer@example.com"}, "role": {"viewer"}})
	must(t, "duplicate user", s, body, 422, "すでにいます")
	s, body, _ = e.post(t, "/users/admin@example.com/update", url.Values{"role": {"viewer"}, "enabled": {"1"}})
	must(t, "demote initial admin", s, body, 422, "降格・無効にできません")
	s, body, _ = e.post(t, "/users/viewer@example.com/update", url.Values{"role": {"viewer"}, "enabled": {"0"}})
	must(t, "disable user", s, body, 200, "を変えました")

	s, body = e.get(t, "/audit")
	must(t, "audit", s, body, 200, "失効")
	for _, want := range []string{"発行", "CA の作成", "利用者の追加", "admin@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit does not contain %q", want)
		}
	}
}

func TestViewer(t *testing.T) {
	e := newTestEnv(t, auth.Dev("viewer@example.com"), true)
	e.db.CreateUser(t.Context(), "viewer@example.com", db.RoleViewer)
	e.svc.CreateTenantCA(t.Context(), ca.System, "tenant-a")
	s, body := e.get(t, "/")
	must(t, "home", s, body, 200, "ダッシュボード")
	if strings.Contains(body, `href="/sign"`) || strings.Contains(body, "テナントのクライアントCA の作成") {
		t.Error("admin controls are shown to a viewer")
	}
	for _, p := range []string{"/sign", "/users"} {
		if s, _ := e.get(t, p); s != 403 {
			t.Errorf("GET %s: %d", p, s)
		}
	}
	for _, p := range []string{"/cas", "/cas/tenant.tenant-a/disable", "/sign", "/users"} {
		if s, _, _ := e.post(t, p, url.Values{"tenant": {"x"}}); s != 403 {
			t.Errorf("POST %s: %d", p, s)
		}
	}
	if c, _ := e.db.CA(t.Context(), "tenant.tenant-a"); c.Status != db.StatusActive {
		t.Error("viewer disabled the CA")
	}
	// 無効にした利用者は入れない。
	e.db.UpdateUser(t.Context(), "viewer@example.com", db.RoleViewer, false)
	if s, _ := e.get(t, "/"); s != 403 {
		t.Errorf("disabled user: %d", s)
	}
}

type rejectVerifier struct{ err error }

func (v rejectVerifier) Verify(context.Context, string) (access.Claims, error) {
	return access.Claims{}, v.err
}

func TestAuthentication(t *testing.T) {
	e := newTestEnv(t, auth.Access(rejectVerifier{access.ErrInvalid}), false)
	s, body := e.get(t, "/")
	must(t, "no token", s, body, 401, "Cloudflare Access")
	s, body = e.get(t, "/healthz")
	must(t, "healthz", s, body, 200, "ok")
	e = newTestEnv(t, auth.Dev("stranger@example.com"), false)
	if s, _ := e.get(t, "/"); s != 403 {
		t.Errorf("unregistered user: %d", s)
	}
	e = newTestEnv(t, auth.Dev("admin@example.com"), false)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/cas", strings.NewReader("tenant=tenant-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("cross-site POST: %d", resp.StatusCode)
	}
	if _, err := e.db.CA(t.Context(), "tenant.tenant-a"); err == nil {
		t.Error("CA was created by a cross-site request")
	}
}
