package ca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/names"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// Material は名前の材料（§5.2）。呼び出し側が渡すのはプロファイルとこれだけで、SAN の文字列そのものは渡せない。
type Material struct {
	Tenant string
	// AP は ap-client のときだけ、Group は group-client のときだけ、Edge は probe-client と tenant-server のときだけ。
	AP, Edge, Group string
}

// plan はプロファイルと名前の材料から決まる、署名する CA と証明書の中身。
type plan struct {
	caID   string
	cn     string
	dns    []string
	uri    string
	eku    x509.ExtKeyUsage
	days   int
	tenant string
}

// planFor はプロファイルと名前の材料を検証し、証明書の中身を決める（§5.2）。
func (s *Service) planFor(profile string, m Material) (plan, error) {
	if err := names.CheckTenant(m.Tenant); err != nil {
		return plan{}, newError(CauseValidation, "tenant", "テナントの名前は、%v", err)
	}
	switch profile {
	case db.ProfileAPClient, db.ProfileGroupClient, db.ProfileProbeClient, db.ProfileTenantServer:
	default:
		return plan{}, newError(CauseValidation, "profile", "プロファイルは ap-client・group-client・probe-client・tenant-server のどれかにしてください")
	}
	if m.Edge != "" && (profile == db.ProfileAPClient || profile == db.ProfileGroupClient) {
		return plan{}, newError(CauseValidation, "edge", "%s にはエッジを与えません", profile)
	}
	if m.AP != "" && profile != db.ProfileAPClient {
		return plan{}, newError(CauseValidation, "ap", "%s には AP を与えません", profile)
	}
	if m.Group != "" && profile != db.ProfileGroupClient {
		return plan{}, newError(CauseValidation, "group", "%s にはグループを与えません", profile)
	}
	switch profile {
	case db.ProfileAPClient:
		if m.AP == names.ProbeAP {
			return plan{}, newError(CauseNameReserved, "ap", "AP の名前 %q はヘルスチェック用に予約しています（probe-client を使います）", names.ProbeAP)
		}
		if err := names.CheckAP(m.AP); err != nil {
			return plan{}, newError(CauseValidation, "ap", "AP の名前は、%v", err)
		}
	case db.ProfileGroupClient:
		if m.Group == names.ProbeAP {
			return plan{}, newError(CauseNameReserved, "group", "グループの名前 %q はヘルスチェック用に予約しています", names.ProbeAP)
		}
		if err := names.CheckGroup(m.Group); err != nil {
			return plan{}, newError(CauseValidation, "group", "グループの名前は、%v", err)
		}
	default:
		if !names.ValidSlug(m.Edge) {
			return plan{}, newError(CauseValidation, "edge", "エッジの名前は、%v", names.ErrSlug)
		}
	}
	switch profile {
	case db.ProfileAPClient:
		return plan{caID: signer.TenantCAID(m.Tenant), cn: names.NASIdentifier(m.Tenant, m.AP),
			uri: names.SANURI(s.URNPrefix, m.Tenant, m.AP), eku: x509.ExtKeyUsageClientAuth, days: s.APCertDays, tenant: m.Tenant}, nil
	case db.ProfileGroupClient:
		return plan{caID: signer.TenantCAID(m.Tenant), cn: names.NASIdentifier(m.Tenant, m.Group),
			uri: names.GroupSANURI(s.URNPrefix, m.Tenant, m.Group), eku: x509.ExtKeyUsageClientAuth, days: s.GroupCertDays, tenant: m.Tenant}, nil
	case db.ProfileProbeClient:
		return plan{caID: signer.TenantCAID(m.Tenant), cn: names.NASIdentifier(m.Tenant, names.ProbeAP),
			uri: names.SANURI(s.URNPrefix, m.Tenant, names.ProbeAP), eku: x509.ExtKeyUsageClientAuth, days: s.APCertDays, tenant: m.Tenant}, nil
	case db.ProfileTenantServer:
		return plan{caID: signer.ServerCAID, cn: m.Tenant + " server " + m.Edge, dns: names.SlotNames(m.Tenant, s.DNSDomain),
			eku: x509.ExtKeyUsageServerAuth, days: s.ServerCertDays, tenant: m.Tenant}, nil
	}
	return plan{}, newError(CauseValidation, "profile", "プロファイルは ap-client・group-client・probe-client・tenant-server のどれかにしてください")
}

// template は証明書のひな形を作る。有効期限は CA の期限を超えない。NotBefore は時計のずれを見込んで 5 分前（§5.2）。
func (p plan) template(pub crypto.PublicKey, caNotAfter, now time.Time) (*x509.Certificate, error) {
	serial, err := signer.NewSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.AddDate(0, 0, p.days)
	if notAfter.After(caNotAfter) {
		notAfter = caNotAfter
	}
	t := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: p.cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{p.eku},
		DNSNames:     p.dns,
		// Authority Key Identifier は crypto/x509 が CA の Subject Key Identifier から付ける。CRL の配布点は付けない。
	}
	if _, ok := pub.(*rsa.PublicKey); ok {
		t.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if p.uri != "" {
		u, err := url.Parse(p.uri)
		if err != nil {
			return nil, err
		}
		t.URIs = []*url.URL{u}
	}
	return t, nil
}
