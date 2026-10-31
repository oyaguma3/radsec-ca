package crlfetch

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPublicAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "100.127.255.255",
		"0.0.0.0", "::", "fc00::1", "fe80::1", "224.0.0.1", "ff02::1", "198.18.0.1", "240.0.0.1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"} {
		if PublicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s must not be public", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "2001:4860:4860::8888"} {
		if !PublicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s must be public", a)
		}
	}
}

func newFetcher(t *testing.T, allowPrivate bool, base string) *Fetcher {
	t.Helper()
	f, err := New(Options{Timeout: 3 * time.Second, AllowPrivate: allowPrivate, MerakiBase: base})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBlocksInternalAddress(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	f := newFetcher(t, false, "https://api.meraki.com/api/v1")
	_, err := f.FetchURL(t.Context(), srv.URL, "", "")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("loopback: %v", err)
	}
	if hit {
		t.Error("the request reached the internal server")
	}
	// 公開のアドレスからのリダイレクトでも、接続の前に同じ確かめをする（名前で指しても同じ）。
	_, err = f.FetchURL(t.Context(), strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), "", "")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("localhost: %v", err)
	}
}

func TestRedirects(t *testing.T) {
	n := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()
	f := newFetcher(t, true, "http://127.0.0.1:1")
	if _, err := f.FetchURL(t.Context(), srv.URL, "", ""); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("redirects: %v", err)
	}
	if n != maxRedirects {
		t.Errorf("followed %d", n)
	}
}

func TestTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxBytes+1))
	}))
	defer srv.Close()
	f := newFetcher(t, true, "http://127.0.0.1:1")
	if _, err := f.FetchURL(t.Context(), srv.URL, "", ""); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("too large: %v", err)
	}
}

func TestParseBytes(t *testing.T) {
	if b, err := ParseBytes([]byte{0x30, 0x01}); err != nil || len(b) != 2 {
		t.Errorf("DER: %v %v", b, err)
	}
	for _, bad := range []string{"", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"} {
		if _, err := ParseBytes([]byte(bad)); err == nil {
			t.Errorf("ParseBytes(%q) = nil", bad)
		}
	}
}

func TestMerakiBaseMustBeHTTPS(t *testing.T) {
	if _, err := New(Options{MerakiBase: "http://api.meraki.com/api/v1"}); err == nil {
		t.Error("http base accepted")
	}
}

// Dashboard API のリダイレクト（シャードへの転送）では、同じドメインの下にだけ API キーを付け直す。
func TestMerakiRedirectKey(t *testing.T) {
	f := newFetcher(t, false, "https://api.meraki.com/api/v1")
	check := f.merakiRedirect("k")
	for _, x := range []struct {
		url string
		ok  bool
	}{
		{"https://n123.meraki.com/api/v1/x", true},
		{"https://api.meraki.com/api/v1/x", true},
		{"https://evil.example.com/x", false},
		{"https://meraki.com.evil.example/x", false},
		{"http://n123.meraki.com/x", false},
	} {
		req := httptest.NewRequest(http.MethodGet, x.url, nil)
		err := check(req, nil)
		if (err == nil) != x.ok {
			t.Errorf("%s: %v", x.url, err)
		}
		if got := req.Header.Get("Authorization"); (got != "") != x.ok {
			t.Errorf("%s: Authorization %q", x.url, got)
		}
	}
}
