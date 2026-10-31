// Package crlfetch は、持ち込みの CA の CRL を外から取ってくる（設計概要 §19.3）。URL から取る方法と、
// Meraki の Dashboard API から取る方法がある。
//
// 本CA は管理面の内部にあるので、取得先の URL で内部へ接続させないよう、接続する瞬間に解決した IP を確かめて
// ループバック・プライベート・リンクローカルなどへの接続を断る（§19.3）。名前解決の結果を後から変える手口にも効く。
package crlfetch

import (
	"context"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// maxBytes は応答の大きさの上限。
	maxBytes = 8 << 20
	// maxRedirects はリダイレクトをたどる回数の上限。
	maxRedirects = 3
	// merakiPath は Meraki の CRL の口（組織の ID を入れる）。
	merakiPath = "/organizations/%s/wireless/devices/radsec/certificates/authorities/crls"
)

// ErrBlockedAddress は、接続先が内部のアドレスだったことを表す。
var ErrBlockedAddress = errors.New("the address is not a public address")

// blockedPrefixes は netip の判定にない、公開でないアドレスの範囲。
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT。WireGuard や Tailscale のアドレスに使う
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// PublicAddr は a が公開のアドレスか。
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Options は Fetcher の設定。
type Options struct {
	// Timeout は 1 回の取得の上限（リダイレクトを含む）。
	Timeout time.Duration
	// AllowPrivate は内部のアドレスへの接続を許す（試験用）。
	AllowPrivate bool
	// MerakiBase は Dashboard API の入口（例 https://api.meraki.com/api/v1）。
	MerakiBase string
}

// Fetcher は CRL を取ってくる。
type Fetcher struct {
	opts Options
	base *url.URL
	tr   *http.Transport
}

// New は Fetcher を作る。
func New(o Options) (*Fetcher, error) {
	base, err := url.Parse(strings.TrimRight(o.MerakiBase, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && !o.AllowPrivate) {
		return nil, fmt.Errorf("the Meraki API base must be an https URL (got %q)", o.MerakiBase)
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !o.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if !PublicAddr(ap.Addr()) {
				return ErrBlockedAddress
			}
			return nil
		}
	}
	return &Fetcher{opts: o, base: base, tr: &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
		DisableKeepAlives:     true, // 取りに行くのは 1 時間に 1 回なので、接続を持たない
	}}, nil
}

// Result は URL からの取得の結果。
type Result struct {
	// DER は CRL の DER（NotModified のときは空）。
	DER []byte
	// ETag と LastModified は次の要求の条件に使う値。
	ETag, LastModified string
	// NotModified は 304 が返ったこと（前の CRL のまま）。
	NotModified bool
}

// CheckURL は取得先の URL の形を確かめる。
func CheckURL(raw string) error {
	if len(raw) > 2048 {
		return errors.New("the URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("the URL must be http:// or https:// with a host name")
	}
	if u.User != nil {
		return errors.New("the URL must not contain a user name or password")
	}
	return nil
}

// checkRedirect はリダイレクトの回数と先の形を確かめる。
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("too many redirects (%d)", maxRedirects)
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to an unsupported scheme %q", req.URL.Scheme)
	}
	return nil
}

// readBody は応答の本文を読む（上限を超えたら誤り）。
func readBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("the response is larger than %d bytes", maxBytes)
	}
	return b, nil
}

// describe は通信の誤りを、利用者に見せる文にする（内部のアドレスを断ったことは、どの段階でも同じ文にする）。
func describe(err error) error {
	if errors.Is(err, ErrBlockedAddress) {
		return ErrBlockedAddress
	}
	return err
}

// FetchURL は url から CRL を取る。etag と lastModified があれば条件つきで要求する。応答は PEM でも DER でも受ける。
func (f *Fetcher) FetchURL(ctx context.Context, rawURL, etag, lastModified string) (Result, error) {
	if err := CheckURL(rawURL); err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	resp, err := (&http.Client{Transport: f.tr, CheckRedirect: checkRedirect}).Do(req)
	if err != nil {
		return Result{}, describe(err)
	}
	defer resp.Body.Close()
	out := Result{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	switch resp.StatusCode {
	case http.StatusNotModified:
		out.NotModified = true
		if out.ETag == "" {
			out.ETag = etag
		}
		if out.LastModified == "" {
			out.LastModified = lastModified
		}
		return out, nil
	case http.StatusOK:
	default:
		return Result{}, fmt.Errorf("the server returned %s", resp.Status)
	}
	body, err := readBody(resp.Body)
	if err != nil {
		return Result{}, err
	}
	if out.DER, err = ParseBytes(body); err != nil {
		return Result{}, err
	}
	return out, nil
}

// ParseBytes は PEM か DER の CRL から DER を取り出す。
func ParseBytes(b []byte) ([]byte, error) {
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "-----BEGIN") {
		if len(b) == 0 {
			return nil, errors.New("the CRL is empty")
		}
		return b, nil
	}
	block, rest := pem.Decode([]byte(s))
	if block == nil || block.Type != "X509 CRL" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("the PEM must contain exactly one X509 CRL")
	}
	return block.Bytes, nil
}

var orgIDPattern = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)

// CheckOrgID は Meraki の組織の ID の形を確かめる。
func CheckOrgID(s string) error {
	if !orgIDPattern.MatchString(s) {
		return errors.New("the organization ID must be letters, digits, _ and - up to 64 characters")
	}
	return nil
}

// merakiRedirect は、リダイレクトの先が同じ入口か同じドメインの下（例 n123.meraki.com）のときだけ API キーを付け直す。
// Go の http.Client は別のホストへのリダイレクトで Authorization を落とす。
func (f *Fetcher) merakiRedirect(key string) func(*http.Request, []*http.Request) error {
	domain := ""
	if _, rest, ok := strings.Cut(f.base.Hostname(), "."); ok && net.ParseIP(f.base.Hostname()) == nil {
		domain = "." + rest
	}
	return func(req *http.Request, via []*http.Request) error {
		if err := checkRedirect(req, via); err != nil {
			return err
		}
		host := req.URL.Hostname()
		sameScheme := req.URL.Scheme == f.base.Scheme
		if sameScheme && (req.URL.Host == f.base.Host || (domain != "" && strings.HasSuffix(host, domain))) {
			req.Header.Set("Authorization", "Bearer "+key)
			return nil
		}
		return fmt.Errorf("redirect to another host %q", host)
	}
}

// FetchMeraki は Dashboard API から組織の CRL を読み、match が受け入れるものの中で最初に見つかった順に DER の一覧を返す。
// 目的の CRL が見つからず、読めなかった残りがあるときは誤りにする（資料にページ送りの説明がないので、取りこぼしを見逃さない）。
// 誤りの文に API キーは入らない。
func (f *Fetcher) FetchMeraki(ctx context.Context, orgID, key string, match func(der []byte) bool) ([][]byte, error) {
	if err := CheckOrgID(orgID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()
	u := f.base.String() + fmt.Sprintf(merakiPath, url.PathEscape(orgID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.New("cannot build the request to the Meraki API")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Transport: f.tr, CheckRedirect: f.merakiRedirect(key)}).Do(req)
	if err != nil {
		return nil, describe(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Meraki API returned %s", resp.Status)
	}
	body, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Items []struct {
			CRL string `json:"crl"`
		} `json:"items"`
		Meta struct {
			Counts struct {
				Items struct {
					Remaining int `json:"remaining"`
				} `json:"items"`
			} `json:"counts"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("the Meraki API returned an unexpected response")
	}
	var out [][]byte
	for _, it := range doc.Items {
		der, err := ParseBytes([]byte(it.CRL))
		if err != nil {
			continue
		}
		if match(der) {
			out = append(out, der)
		}
	}
	if len(out) == 0 {
		if n := doc.Meta.Counts.Items.Remaining; n > 0 {
			return nil, fmt.Errorf("the CRL was not found and %d items could not be read", n)
		}
		return nil, errors.New("the Meraki API has no CRL issued by this CA")
	}
	return out, nil
}
