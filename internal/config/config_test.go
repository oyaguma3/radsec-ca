package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setBase(t *testing.T) {
	t.Helper()
	t.Setenv("CA_ORG", "Example Org")
	t.Setenv("CA_URN_PREFIX", "example")
	t.Setenv("CA_DNS_DOMAIN", "radsec.example.net")
	t.Setenv("CA_INITIAL_ADMIN_EMAIL", "Admin@Example.com")
	t.Setenv("CA_DEV_USER_EMAIL", "admin@example.com")
	t.Setenv("CA_GUI_ADDR", "127.0.0.1:8448")
}

func TestLoadDefaults(t *testing.T) {
	setBase(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DBPath != "/data/radsec-ca.db" || c.KEKFile != "/run/secrets/kek" || c.TLSDir != "/data/tls" || c.APIAddr != ":9448" || c.PublishAddr != ":8449" {
		t.Errorf("defaults: %+v", c)
	}
	if c.APCertDays != 730 || c.ServerCertDays != 365 || c.CRLValidity != 7*24*time.Hour || c.CRLRefresh != 24*time.Hour {
		t.Errorf("validity: %+v", c)
	}
	if c.InitialAdminEmail != "admin@example.com" || c.APIEnabled() || !c.DevMode() {
		t.Errorf("auth: %+v", c)
	}
}

func TestAdminClientsFile(t *testing.T) {
	setBase(t)
	file := filepath.Join(t.TempDir(), "admin-clients")
	t.Setenv("CA_ADMIN_CLIENTS_FILE", file)
	// ファイルがなければ管理API を待ち受けない（単独モード）。
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.APIEnabled() {
		t.Error("API enabled without the file")
	}
	if err := os.WriteFile(file, []byte("provisioner="+strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CA_TLS_HOSTS", "100.64.0.10, ca.example.net")
	if c, err = Load(); err != nil {
		t.Fatal(err)
	}
	if !c.APIEnabled() || len(c.TLSHosts) != 2 {
		t.Errorf("admin: %v %v", c.APIEnabled(), c.TLSHosts)
	}
	t.Setenv("CA_TLS_HOSTS", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CA_TLS_HOSTS") {
		t.Errorf("no TLS hosts: %v", err)
	}
	// 環境変数の古い設定は黙って無視せず、誤りにする。
	t.Setenv("CA_TLS_HOSTS", "ca.example.net")
	t.Setenv("CA_ADMIN_CLIENTS", "provisioner="+strings.Repeat("ab", 32))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CA_ADMIN_CLIENTS is no longer used") {
		t.Errorf("old setting: %v", err)
	}
}

func TestBroughtSettings(t *testing.T) {
	setBase(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.BroughtCRLRefresh != time.Hour || c.BroughtCRLTimeout != 20*time.Second || c.BroughtCRLAllowPrivate ||
		c.MerakiAPIBase != "https://api.meraki.com/api/v1" || c.GroupCertDays != 730 || c.AuditDir != "/data/audit" || c.AuditRetentionDays != 14 {
		t.Errorf("defaults: %+v", c)
	}
	t.Setenv("CA_BROUGHT_CRL_TIMEOUT", "26s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CA_BROUGHT_CRL_TIMEOUT") {
		t.Errorf("timeout: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct{ env, value, want string }{
		{"CA_ORG", "", "CA_ORG"},
		{"CA_ORG", "a\nb", "CA_ORG"},
		{"CA_URN_PREFIX", "a:b", "CA_URN_PREFIX"},
		{"CA_DNS_DOMAIN", "*.example.net", "CA_DNS_DOMAIN"},
		{"CA_DB_PATH", "ca.db", "CA_DB_PATH"},
		{"CA_AP_CERT_DAYS", "0", "CA_AP_CERT_DAYS"},
		{"CA_CRL_REFRESH", "200h", "shorter"},
		{"CA_INITIAL_ADMIN_EMAIL", "", "CA_INITIAL_ADMIN_EMAIL"},
		{"CA_GUI_ADDR", ":8448", "loopback"},
		{"CA_ACCESS_AUD", "aud", "cannot be used with"},
	}
	for _, tc := range cases {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			setBase(t)
			t.Setenv(tc.env, tc.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load() = %v, want %q", err, tc.want)
			}
		})
	}
}
