package db

import (
	"os"
	"path/filepath"
	"testing"
)

// 段階 2 の DB（移行 0001 まで）に行を入れてから 0002 を適用し、行と順序が残り、外部キーと新しい制約が効くことを確かめる。
func TestMigrate0002KeepsRows(t *testing.T) {
	ctx := t.Context()
	d, err := Open(ctx, filepath.Join(t.TempDir(), "ca.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	first, err := os.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.ExecContext(ctx, string(first)); err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`INSERT INTO schema_migrations VALUES (1, 'init', 1)`,
		`INSERT INTO cas (id, kind, tenant, cert_der, key_enc, key_nonce, kek_id, status, crl_number, not_after, created_at) VALUES
			('server', 'server', '', x'01', x'02', x'03', 'k', 'active', 1, 10, 1),
			('tenant.a', 'tenant-client', 'a', x'04', x'05', x'06', 'k', 'disabled', 2, 10, 2)`,
		`INSERT INTO certs (rowid, serial, ca_id, profile, tenant, ap, cn, not_before, not_after, cert_der, pubkey_sha256, created_at) VALUES
			(5, 'aa', 'tenant.a', 'ap-client', 'a', 'x', 'a-x', 1, 2, x'07', 'p', 3),
			(9, 'bb', 'tenant.a', 'probe-client', 'a', '', 'a-probe', 1, 2, x'08', 'q', 4)`,
		`INSERT INTO crls (ca_id, number, this_update, next_update, der, created_at) VALUES ('tenant.a', 2, 1, 2, x'09', 3)`,
	}
	for _, s := range stmts {
		if _, err := d.sql.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := d.Migrate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != 2 {
		t.Fatalf("applied %v", applied)
	}
	c, err := d.CA(ctx, "tenant.a")
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusDisabled || c.CRLNumber != 2 || string(c.KeyEnc) != "\x05" || c.CRLSource != CRLSourceIssued || !c.SelfSigned {
		t.Errorf("ca: %+v", c)
	}
	page, err := d.Certs(ctx, CertFilter{Limit: 10})
	if err != nil || len(page.Certs) != 2 || page.Certs[0].Serial != "bb" || page.Certs[1].Serial != "aa" {
		t.Errorf("certs: %+v %v", page, err)
	}
	crl, err := d.LatestCRL(ctx, "tenant.a")
	if err != nil || crl.Number != 2 || crl.ExtNumber != "" {
		t.Errorf("crl: %+v %v", crl, err)
	}
	// 外部キーが効いている。
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO crls (ca_id, number, this_update, next_update, der, created_at) VALUES ('none', 1, 1, 2, x'09', 3)`); err == nil {
		t.Error("foreign key of crls is not enforced")
	}
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO certs (serial, ca_id, profile, tenant, cn, not_before, not_after, cert_der, pubkey_sha256, created_at) VALUES ('cc', 'none', 'ap-client', 'a', 'c', 1, 2, x'07', 'p', 3)`); err == nil {
		t.Error("foreign key of certs is not enforced")
	}
	// 新しい制約: 持ち込みの CA の種類と group-client を受ける。有効な CA の中でフィンガープリントは一意。
	b := CA{ID: "brought.a.x", Kind: KindTenantBrought, Tenant: "a", CertDER: []byte{1}, Status: StatusActive, Fingerprint: "ff", CRLSource: CRLSourceNone}
	if err := d.InsertCA(ctx, b); err != nil {
		t.Fatal(err)
	}
	b2 := b
	b2.ID = "brought.b.x"
	if err := d.InsertCA(ctx, b2); err == nil {
		t.Error("the same fingerprint was accepted")
	}
	if ok, err := d.DisableBrought(ctx, b.ID); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := d.InsertCA(ctx, b2); err != nil {
		t.Errorf("after disable: %v", err)
	}
	// 発行した CA は取得先を持てない。
	bad := CA{ID: "tenant.c", Kind: KindTenantClient, Tenant: "c", CertDER: []byte{1}, Status: StatusActive, CRLSource: CRLSourceURL}
	if err := d.InsertCA(ctx, bad); err == nil {
		t.Error("tenant-client with a CRL source was accepted")
	}
}
