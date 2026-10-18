package ca

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// バックアップから戻して起動でき（KEK の確認が通り）、発行と失効を続けられること（§14）。
func TestBackupRestore(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.svc.CreateTenantCA(ctx, System, "tenant-a")
	issued := issueAP(t, e, "ap-001")
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := e.db.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Backup(ctx, backup); err == nil {
		t.Error("Backup overwrote an existing file")
	}
	d, err := db.Open(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	k, _ := kek.New(bytes.Repeat([]byte{7}, kek.Size))
	sig := &signer.Local{DB: d, KEK: k}
	if n, err := sig.Check(ctx); err != nil || n != 2 {
		t.Fatalf("Check on the backup = %d, %v", n, err)
	}
	svc := New(e.svc.Options)
	svc.DB, svc.Signer = d, sig
	if changed, err := svc.Revoke(ctx, System, issued.Cert.Serial, "superseded"); err != nil || !changed {
		t.Fatalf("Revoke on the backup = %v, %v", changed, err)
	}
	if _, err := svc.Issue(ctx, System, IssueRequest{Profile: db.ProfileAPClient, Material: Material{Tenant: "tenant-a", AP: "ap-002"}, CSR: csr(t, p256(t))}); err != nil {
		t.Fatalf("Issue on the backup: %v", err)
	}
	// 違う KEK では、戻した DB でも起動しない。
	other, _ := kek.New(bytes.Repeat([]byte{8}, kek.Size))
	if _, err := (&signer.Local{DB: d, KEK: other}).Check(ctx); err == nil {
		t.Error("the backup started with another KEK")
	}
}
