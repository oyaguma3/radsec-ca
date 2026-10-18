// Package config は環境変数（接頭辞 CA_）から設定を読む（設計概要 §12）。
package config

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/oyaguma3/radsec-ca/internal/names"
)

// Config は本CA の設定。
type Config struct {
	LogLevel slog.Level

	// Org は CA の Subject の O と CN に入れる組織の名前。
	Org string
	// URNPrefix と DNSDomain は名前の規則の値（エッジの EDGE_URN_PREFIX・EDGE_DNS_DOMAIN と同じ値にそろえる）。
	URNPrefix, DNSDomain string

	// DBPath は SQLite のファイル、KEKFile は暗号化の鍵（KEK）のファイル。
	DBPath, KEKFile string
	// TLSDir は管理API のサーバー証明書と鍵を置くディレクトリ（DB と同じディレクトリの tls）。
	TLSDir string

	// AdminClients は管理クライアントのフィンガープリント（SHA-256、16 進小文字）から識別名を引く。空なら API を待ち受けない。
	AdminClients map[string]string
	// TLSHosts は管理API のサーバー証明書の SAN。
	TLSHosts []string

	// APIAddr・PublishAddr・GUIAddr は待ち受けのアドレス。
	APIAddr, PublishAddr, GUIAddr string

	// AccessTeamDomain と AccessAUDs は Cloudflare Access の設定、InitialAdminEmail は最初の管理者。
	AccessTeamDomain  string
	AccessAUDs        []string
	InitialAdminEmail string
	// DevUserEmail は開発用の設定（JWT を検証せず、この利用者として動かす。画面がループバックで待ち受けるときだけ）。
	DevUserEmail string

	// APCertDays と ServerCertDays は有効期限（日。§5.2）。
	APCertDays, ServerCertDays int
	// CRLValidity と CRLRefresh は CRL の nextUpdate までの長さと作り直しの間隔（§7.2）。
	CRLValidity, CRLRefresh time.Duration
}

// DevMode は開発用の設定で動くか。
func (c Config) DevMode() bool { return c.DevUserEmail != "" }

// APIEnabled は管理API を待ち受けるか。
func (c Config) APIEnabled() bool { return len(c.AdminClients) > 0 }

var (
	clientNamePattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostnamePattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	emailPattern       = regexp.MustCompile(`^[a-z0-9._-]+@[a-z0-9._-]+$`)
)

// ValidEmail は利用者のメールアドレスの形か（監査ログの操作者に使う。provisioner の X-Operator-Id と同じ文字）。
func ValidEmail(s string) bool { return len(s) <= 64 && emailPattern.MatchString(s) }

// NormalizeEmail はメールアドレスを小文字にし、前後の空白を落とす。
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// CheckOrg は組織の名前を検証する（1〜64 文字、制御文字なし）。
func CheckOrg(s string) error {
	if s == "" || len([]rune(s)) > 64 || strings.TrimSpace(s) != s {
		return errors.New("must be 1 to 64 characters without leading or trailing spaces")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// Load は環境変数から設定を読む。誤りはまとめて返す。
func Load() (Config, error) {
	c := Config{
		Org:         os.Getenv("CA_ORG"),
		URNPrefix:   os.Getenv("CA_URN_PREFIX"),
		DNSDomain:   strings.ToLower(os.Getenv("CA_DNS_DOMAIN")),
		DBPath:      cmp.Or(os.Getenv("CA_DB_PATH"), "/data/radsec-ca.db"),
		KEKFile:     cmp.Or(os.Getenv("CA_KEK_FILE"), "/run/secrets/kek"),
		APIAddr:     cmp.Or(os.Getenv("CA_API_ADDR"), ":9448"),
		PublishAddr: cmp.Or(os.Getenv("CA_PUBLISH_ADDR"), ":8449"),
		GUIAddr:     cmp.Or(os.Getenv("CA_GUI_ADDR"), ":8448"),
	}
	var errs []error
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("LOG_LEVEL: %w", err))
		}
	}
	if err := CheckOrg(c.Org); err != nil {
		errs = append(errs, fmt.Errorf("CA_ORG: %w", err))
	}
	if err := names.CheckURNPrefix(c.URNPrefix); err != nil {
		errs = append(errs, fmt.Errorf("CA_URN_PREFIX: %w", err))
	}
	if err := names.CheckDomain(c.DNSDomain); err != nil {
		errs = append(errs, fmt.Errorf("CA_DNS_DOMAIN: %w", err))
	}
	for name, p := range map[string]string{"CA_DB_PATH": c.DBPath, "CA_KEK_FILE": c.KEKFile} {
		if !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("%s: must be an absolute path", name))
		}
	}
	c.TLSDir = filepath.Join(filepath.Dir(c.DBPath), "tls")
	for name, a := range map[string]string{"CA_API_ADDR": c.APIAddr, "CA_PUBLISH_ADDR": c.PublishAddr, "CA_GUI_ADDR": c.GUIAddr} {
		if _, _, err := net.SplitHostPort(a); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	errs = append(errs, c.loadAdmin()...)
	errs = append(errs, c.loadValidity()...)
	errs = append(errs, c.loadAuth()...)
	return c, errors.Join(errs...)
}

// loadAdmin は管理クライアントとサーバー証明書の SAN を読む。
func (c *Config) loadAdmin() []error {
	var errs []error
	clients, err := ParseAdminClients(os.Getenv("CA_ADMIN_CLIENTS"))
	if err != nil {
		errs = append(errs, fmt.Errorf("CA_ADMIN_CLIENTS: %w", err))
	}
	c.AdminClients = clients
	for h := range strings.SplitSeq(os.Getenv("CA_TLS_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, err := netip.ParseAddr(h); err != nil && !hostnamePattern.MatchString(h) {
			errs = append(errs, fmt.Errorf("CA_TLS_HOSTS: %q is neither an IP address nor a host name", h))
			continue
		}
		c.TLSHosts = append(c.TLSHosts, h)
	}
	if c.APIEnabled() && len(c.TLSHosts) == 0 {
		errs = append(errs, errors.New("CA_TLS_HOSTS is required when CA_ADMIN_CLIENTS is set (the SAN of the API server certificate, e.g. the tunnel address)"))
	}
	return errs
}

// ParseAdminClients は「識別名=フィンガープリント,...」を読む（provisioner の PROVISIONER_ADMIN_CLIENTS と同じ形）。
func ParseAdminClients(s string) (map[string]string, error) {
	out := map[string]string{}
	names := map[string]bool{}
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, fp, ok := strings.Cut(entry, "=")
		fp = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
		name = strings.TrimSpace(name)
		switch {
		case !ok || !clientNamePattern.MatchString(name):
			return nil, fmt.Errorf("%q: must be name=fingerprint (name: letters, digits and ._- up to 64 characters)", entry)
		case !fingerprintPattern.MatchString(fp):
			return nil, fmt.Errorf("%q: the fingerprint must be the SHA-256 of the certificate in hexadecimal (64 characters)", entry)
		case names[name] || out[fp] != "":
			return nil, fmt.Errorf("%q: duplicate name or fingerprint", entry)
		}
		names[name] = true
		out[fp] = name
	}
	return out, nil
}

func (c *Config) loadValidity() []error {
	var errs []error
	for _, d := range []struct {
		env      string
		dst      *int
		def      int
		min, max int
	}{
		{"CA_AP_CERT_DAYS", &c.APCertDays, 730, 1, 3650},
		{"CA_SERVER_CERT_DAYS", &c.ServerCertDays, 365, 1, 3650},
	} {
		*d.dst = d.def
		if v := os.Getenv(d.env); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < d.min || n > d.max {
				errs = append(errs, fmt.Errorf("%s: must be an integer between %d and %d", d.env, d.min, d.max))
				continue
			}
			*d.dst = n
		}
	}
	for _, d := range []struct {
		env      string
		dst      *time.Duration
		def      time.Duration
		min, max time.Duration
	}{
		{"CA_CRL_VALIDITY", &c.CRLValidity, 7 * 24 * time.Hour, time.Hour, 90 * 24 * time.Hour},
		{"CA_CRL_REFRESH", &c.CRLRefresh, 24 * time.Hour, time.Minute, 30 * 24 * time.Hour},
	} {
		*d.dst = d.def
		if v := os.Getenv(d.env); v != "" {
			x, err := time.ParseDuration(v)
			if err != nil || x < d.min || x > d.max {
				errs = append(errs, fmt.Errorf("%s: must be a duration between %s and %s", d.env, d.min, d.max))
				continue
			}
			*d.dst = x
		}
	}
	if c.CRLRefresh >= c.CRLValidity {
		errs = append(errs, errors.New("CA_CRL_REFRESH must be shorter than CA_CRL_VALIDITY"))
	}
	return errs
}

// loadAuth は画面の利用者の識別の設定を読む。Access と開発用の設定のどちらか一方だけを受け付ける。
func (c *Config) loadAuth() []error {
	var errs []error
	c.InitialAdminEmail = NormalizeEmail(os.Getenv("CA_INITIAL_ADMIN_EMAIL"))
	switch {
	case c.InitialAdminEmail == "":
		errs = append(errs, errors.New("CA_INITIAL_ADMIN_EMAIL is not set"))
	case !ValidEmail(c.InitialAdminEmail):
		errs = append(errs, errors.New("CA_INITIAL_ADMIN_EMAIL: must be an email address of up to 64 characters using only letters, digits and ._-"))
	}
	c.AccessTeamDomain = strings.ToLower(strings.TrimSpace(os.Getenv("CA_ACCESS_TEAM_DOMAIN")))
	for v := range strings.SplitSeq(os.Getenv("CA_ACCESS_AUD"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			c.AccessAUDs = append(c.AccessAUDs, v)
		}
	}
	c.DevUserEmail = NormalizeEmail(os.Getenv("CA_DEV_USER_EMAIL"))
	access := c.AccessTeamDomain != "" || len(c.AccessAUDs) > 0
	switch {
	case access && c.DevUserEmail != "":
		errs = append(errs, errors.New("CA_DEV_USER_EMAIL cannot be used with the Cloudflare Access settings (CA_ACCESS_*)"))
	case access:
		if c.AccessTeamDomain == "" || len(c.AccessAUDs) == 0 {
			errs = append(errs, errors.New("both CA_ACCESS_TEAM_DOMAIN and CA_ACCESS_AUD are required"))
		} else if !strings.Contains(c.AccessTeamDomain, ".") || !hostnamePattern.MatchString(c.AccessTeamDomain) {
			errs = append(errs, errors.New("CA_ACCESS_TEAM_DOMAIN: must be a host name such as example.cloudflareaccess.com"))
		}
	case c.DevUserEmail != "":
		if !ValidEmail(c.DevUserEmail) {
			errs = append(errs, errors.New("CA_DEV_USER_EMAIL: must be an email address of up to 64 characters using only letters, digits and ._-"))
		}
		if host, _, err := net.SplitHostPort(c.GUIAddr); err == nil && !isLoopback(host) {
			errs = append(errs, fmt.Errorf("CA_DEV_USER_EMAIL can be used only when CA_GUI_ADDR is a loopback address (got %q)", c.GUIAddr))
		}
	default:
		errs = append(errs, errors.New("set CA_ACCESS_TEAM_DOMAIN and CA_ACCESS_AUD (Cloudflare Access), or CA_DEV_USER_EMAIL for development"))
	}
	return errs
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
