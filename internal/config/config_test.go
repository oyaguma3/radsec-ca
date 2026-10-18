package config

import (
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

func TestAdminClients(t *testing.T) {
	setBase(t)
	fp := strings.Repeat("ab", 32)
	t.Setenv("CA_ADMIN_CLIENTS", "provisioner="+strings.ToUpper(fp))
	t.Setenv("CA_TLS_HOSTS", "100.64.0.10, ca.example.net")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminClients[fp] != "provisioner" || len(c.TLSHosts) != 2 || !c.APIEnabled() {
		t.Errorf("admin: %+v %v", c.AdminClients, c.TLSHosts)
	}
	t.Setenv("CA_TLS_HOSTS", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CA_TLS_HOSTS") {
		t.Errorf("no TLS hosts: %v", err)
	}
	for _, bad := range []string{"provisioner", "p=short", "bad name=" + fp, "a=" + fp + ",b=" + fp} {
		if _, err := ParseAdminClients(bad); err == nil {
			t.Errorf("ParseAdminClients(%q) = nil", bad)
		}
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
