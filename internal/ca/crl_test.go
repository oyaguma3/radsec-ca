package ca

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
)

func latestCRL(t *testing.T, e *env, caID string) *x509.RevocationList {
	t.Helper()
	c, err := e.db.LatestCRL(t.Context(), caID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(c.DER)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := e.db.CA(t.Context(), caID)
	caCert, _ := x509.ParseCertificate(ca.CertDER)
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	return crl
}

func issueAP(t *testing.T, e *env, ap string) Issued {
	t.Helper()
	got, err := e.svc.Issue(t.Context(), System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: ap}, CSR: csr(t, p256(t))})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRevokeAndCRL(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	crl := latestCRL(t, e, "tenant.tenant-a")
	if crl.Number.Int64() != 1 || len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("first CRL: #%v %d entries", crl.Number, len(crl.RevokedCertificateEntries))
	}
	if d := crl.NextUpdate.Sub(crl.ThisUpdate); d != 7*24*time.Hour {
		t.Errorf("nextUpdate - thisUpdate = %v", d)
	}

	a := issueAP(t, e, "ap-001")
	b := issueAP(t, e, "ap-002")
	changed, err := e.svc.Revoke(ctx, Actor{Operator: "op", Source: db.SourceAPI}, a.Cert.Serial, "keyCompromise")
	if err != nil || !changed {
		t.Fatalf("Revoke = %v, %v", changed, err)
	}
	crl = latestCRL(t, e, "tenant.tenant-a")
	if crl.Number.Int64() != 2 || len(crl.RevokedCertificateEntries) != 1 ||
		crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != a.Cert.Serial || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Fatalf("CRL after revoke: #%v %+v", crl.Number, crl.RevokedCertificateEntries)
	}
	// もう一度失効させても成功として扱い、何もしない（理由も変えない、CRL も作り直さない）。
	if changed, err := e.svc.Revoke(ctx, System, a.Cert.Serial, "superseded"); err != nil || changed {
		t.Errorf("second Revoke = %v, %v", changed, err)
	}
	if rec, _ := e.db.Cert(ctx, a.Cert.Serial); rec.RevokeReason != "keyCompromise" || rec.Status(time.Now()) != "revoked" {
		t.Errorf("record = %+v", rec)
	}
	if latestCRL(t, e, "tenant.tenant-a").Number.Int64() != 2 {
		t.Error("CRL was published again for an already revoked certificate")
	}
	if _, err := e.svc.Revoke(ctx, System, "ffff", "unspecified"); cause(err) != CauseCertNotFound {
		t.Errorf("unknown serial: %v", err)
	}
	if _, err := e.svc.Revoke(ctx, System, b.Cert.Serial, "certificateHold"); cause(err) != CauseValidation {
		t.Errorf("certificateHold: %v", err)
	}
	// 期限の切れた証明書は CRL に載せない（期限を過ぎた時刻で作り直す）。
	e.svc.Now = func() time.Time { return time.Now().AddDate(3, 0, 0) }
	if n := e.svc.RefreshCRLs(ctx); n != 0 {
		t.Fatalf("RefreshCRLs failed %d", n)
	}
	if crl := latestCRL(t, e, "tenant.tenant-a"); len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("expired revoked certificate is still listed: %+v", crl.RevokedCertificateEntries)
	}
}

func TestRefreshCRLs(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	base := time.Now()
	number := func(id string) int64 { return latestCRL(t, e, id).Number.Int64() }
	// 作り直しの時期でなければ作らない。
	e.svc.Now = func() time.Time { return base.Add(time.Hour) }
	e.svc.RefreshCRLs(ctx)
	if number("server") != 1 || number("tenant.tenant-a") != 1 {
		t.Error("CRL was published before it was due")
	}
	// 前の CRL から CRLRefresh（1 日）が経ったら作り直す。
	e.svc.Now = func() time.Time { return base.Add(25 * time.Hour) }
	e.svc.RefreshCRLs(ctx)
	if number("server") != 2 || number("tenant.tenant-a") != 2 {
		t.Error("CRL was not refreshed")
	}
	// nextUpdate までが 1 日を切ったら作り直す（作り直しの間隔を長くしても）。
	e.svc.CRLRefresh = 30 * 24 * time.Hour
	e.svc.Now = func() time.Time { return base.Add(25*time.Hour + 6*24*time.Hour + time.Hour) }
	e.svc.RefreshCRLs(ctx)
	if number("server") != 3 {
		t.Error("CRL near nextUpdate was not refreshed")
	}
	if len(e.svc.CRLErrors()) != 0 {
		t.Errorf("CRLErrors = %v", e.svc.CRLErrors())
	}
	// CRL は直近の 30 個を残す。
	e.svc.CRLRefresh = time.Minute
	for i := range 35 {
		e.svc.Now = func() time.Time { return base.Add(time.Duration(40+i) * 24 * time.Hour) }
		e.svc.RefreshCRLs(ctx)
	}
	crls, _ := e.db.CRLs(ctx, "server")
	if len(crls) != 30 || crls[0].Number != 38 {
		t.Errorf("kept %d CRLs, latest #%d", len(crls), crls[0].Number)
	}
}

func TestDisableCA(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	a := issueAP(t, e, "ap-001")
	b := issueAP(t, e, "ap-002")
	if err := e.svc.DisableCA(ctx, System, "tenant.tenant-a"); err != nil {
		t.Fatal(err)
	}
	c, _ := e.db.CA(ctx, "tenant.tenant-a")
	if c.Status != db.StatusDisabled || c.DisabledAt.IsZero() {
		t.Errorf("CA = %+v", c)
	}
	crl := latestCRL(t, e, "tenant.tenant-a")
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("CRL entries = %d", len(crl.RevokedCertificateEntries))
	}
	for _, s := range []string{a.Cert.Serial, b.Cert.Serial} {
		if rec, _ := e.db.Cert(ctx, s); rec.RevokeReason != "cessationOfOperation" {
			t.Errorf("%s reason = %s", s, rec.RevokeReason)
		}
	}
	// 停止した CA の CRL も作り続ける。
	e.svc.Now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	e.svc.RefreshCRLs(ctx)
	if n := latestCRL(t, e, "tenant.tenant-a").Number.Int64(); n != 3 {
		t.Errorf("CRL of a disabled CA: #%d", n)
	}
	if err := e.svc.DisableCA(ctx, System, "tenant.tenant-a"); err != nil {
		t.Errorf("second DisableCA = %v", err)
	}
	if err := e.svc.DisableCA(ctx, System, "server"); cause(err) != CauseValidation {
		t.Errorf("disable server: %v", err)
	}
	if err := e.svc.DisableCA(ctx, System, "tenant.none"); cause(err) != CauseCANotFound {
		t.Errorf("disable unknown: %v", err)
	}
}
