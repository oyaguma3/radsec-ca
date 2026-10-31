package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CA の種類と状態（§5.1、§19.2）、CRL の取得先（§19.3）。
const (
	KindServer        = "server"
	KindTenantClient  = "tenant-client"
	KindTenantBrought = "tenant-brought"

	StatusActive   = "active"
	StatusDisabled = "disabled"

	CRLSourceIssued = "issued"
	CRLSourceURL    = "url"
	CRLSourceMeraki = "meraki"
	CRLSourceUpload = "upload"
	CRLSourceNone   = "none"
)

// CA は CA の記録。KeyEnc は暗号化した秘密鍵（復号は internal/kek）。持ち込みの CA には鍵がない。
type CA struct {
	ID         string
	Kind       string
	Tenant     string
	CertDER    []byte
	KeyEnc     []byte
	KeyNonce   []byte
	KEKID      string
	Status     string
	CRLNumber  int64
	NotAfter   time.Time
	CreatedAt  time.Time
	DisabledAt time.Time
	// SelfSigned は証明書が自己署名か、Fingerprint は持ち込みの CA の証明書の SHA-256（16 進小文字）。
	SelfSigned  bool
	Fingerprint string
	// CRLSource は CRL の取得先。CRLURL と MerakiOrgID は取得先の値、MerakiKeyEnc は暗号化した API キー。
	CRLSource      string
	CRLURL         string
	MerakiOrgID    string
	MerakiKeyEnc   []byte
	MerakiKeyNonce []byte
	// 取得の状態（§19.3）。
	CRLETag      string
	CRLModified  string
	CRLCheckedAt time.Time
	CRLOKAt      time.Time
	CRLFailures  int
	CRLLastError string
	// テナント専用の確認と CRL なしの了承（操作者と時刻）。
	TenantOnlyBy string
	TenantOnlyAt time.Time
	NoCRLBy      string
	NoCRLAt      time.Time
}

const caColumns = `id, kind, tenant, cert_der, key_enc, key_nonce, kek_id, status, crl_number, not_after, created_at, disabled_at,
	self_signed, fingerprint, crl_source, crl_url, meraki_org_id, meraki_key_enc, meraki_key_nonce, crl_etag, crl_modified,
	crl_checked_at, crl_ok_at, crl_failures, crl_last_error, tenant_only_by, tenant_only_at, no_crl_by, no_crl_at`

func scanCA(s interface{ Scan(...any) error }) (CA, error) {
	var c CA
	var na, ca, da, checked, ok, tenantOnly, noCRL int64
	if err := s.Scan(&c.ID, &c.Kind, &c.Tenant, &c.CertDER, &c.KeyEnc, &c.KeyNonce, &c.KEKID, &c.Status, &c.CRLNumber, &na, &ca, &da,
		&c.SelfSigned, &c.Fingerprint, &c.CRLSource, &c.CRLURL, &c.MerakiOrgID, &c.MerakiKeyEnc, &c.MerakiKeyNonce, &c.CRLETag, &c.CRLModified,
		&checked, &ok, &c.CRLFailures, &c.CRLLastError, &c.TenantOnlyBy, &tenantOnly, &c.NoCRLBy, &noCRL); err != nil {
		return CA{}, err
	}
	c.NotAfter, c.CreatedAt, c.DisabledAt = fromMillis(na), fromMillis(ca), fromMillis(da)
	c.CRLCheckedAt, c.CRLOKAt, c.TenantOnlyAt, c.NoCRLAt = fromMillis(checked), fromMillis(ok), fromMillis(tenantOnly), fromMillis(noCRL)
	return c, nil
}

func insertCA(ctx context.Context, e interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, c CA) error {
	// nil の BLOB は NOT NULL に反するので、空にして入れる。
	blob := func(b []byte) []byte {
		if b == nil {
			return []byte{}
		}
		return b
	}
	if c.CRLSource == "" {
		c.CRLSource = CRLSourceIssued
	}
	_, err := e.ExecContext(ctx, "INSERT INTO cas ("+caColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.Kind, c.Tenant, c.CertDER, blob(c.KeyEnc), blob(c.KeyNonce), c.KEKID, c.Status, c.CRLNumber,
		millis(c.NotAfter), millis(c.CreatedAt), millis(c.DisabledAt), c.SelfSigned, c.Fingerprint, c.CRLSource, c.CRLURL, c.MerakiOrgID,
		blob(c.MerakiKeyEnc), blob(c.MerakiKeyNonce), c.CRLETag, c.CRLModified, millis(c.CRLCheckedAt), millis(c.CRLOKAt), c.CRLFailures, c.CRLLastError,
		c.TenantOnlyBy, millis(c.TenantOnlyAt), c.NoCRLBy, millis(c.NoCRLAt))
	if isUnique(err) {
		return fmt.Errorf("insert ca %s: %w", c.ID, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("insert ca %s: %w", c.ID, err)
	}
	return nil
}

// InsertCA は CA を入れる。同じ ID があれば ErrConflict。
func (d *DB) InsertCA(ctx context.Context, c CA) error { return insertCA(ctx, d.sql, c) }

// CA は ID の CA を返す。なければ ErrNotFound。
func (d *DB) CA(ctx context.Context, id string) (CA, error) {
	c, err := scanCA(d.sql.QueryRowContext(ctx, "SELECT "+caColumns+" FROM cas WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, ErrNotFound
	}
	if err != nil {
		return CA{}, fmt.Errorf("get ca %s: %w", id, err)
	}
	return c, nil
}

// CAs はすべての CA を返す（server が先頭で、ほかは ID の順）。
func (d *DB) CAs(ctx context.Context) ([]CA, error) { return d.listCAs(ctx, "", nil) }

// TenantCAs はテナント tenant の CA（発行した CA と持ち込みの CA）を ID の順に返す。
func (d *DB) TenantCAs(ctx context.Context, tenant string) ([]CA, error) {
	return d.listCAs(ctx, "WHERE tenant = ?", []any{tenant})
}

func (d *DB) listCAs(ctx context.Context, where string, args []any) ([]CA, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT "+caColumns+" FROM cas "+where+" ORDER BY kind != 'server', id", args...)
	if err != nil {
		return nil, fmt.Errorf("list cas: %w", err)
	}
	defer rows.Close()
	var out []CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("list cas: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ActiveBroughtByFingerprint は、フィンガープリントが fp の有効な持ち込みの CA を返す。なければ ErrNotFound。
func (d *DB) ActiveBroughtByFingerprint(ctx context.Context, fp string) (CA, error) {
	c, err := scanCA(d.sql.QueryRowContext(ctx, "SELECT "+caColumns+" FROM cas WHERE kind = 'tenant-brought' AND status = 'active' AND fingerprint = ?", fp))
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, ErrNotFound
	}
	if err != nil {
		return CA{}, fmt.Errorf("brought ca by fingerprint: %w", err)
	}
	return c, nil
}

// BroughtDue は、取りに行く時期の持ち込みの CA（有効で、取得先が url か meraki で、最後に試みたのが before より前）を返す。
func (d *DB) BroughtDue(ctx context.Context, before time.Time) ([]CA, error) {
	return d.listCAs(ctx, "WHERE kind = 'tenant-brought' AND status = 'active' AND crl_source IN ('url', 'meraki') AND crl_checked_at <= ?", []any{millis(before)})
}

// DisableCA は CA を停止する（発行しない。CRL は作り続ける。§7.4）。停止していれば何もせず false を返す。
func (d *DB) DisableCA(ctx context.Context, id string) (bool, error) {
	res, err := d.sql.ExecContext(ctx, "UPDATE cas SET status = 'disabled', disabled_at = ? WHERE id = ? AND status = 'active'",
		millis(d.now()), id)
	if err != nil {
		return false, fmt.Errorf("disable ca %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DisableBrought は持ち込みの CA を停止し、Meraki の API キーを消す（§19.2）。停止していれば何もせず false を返す。
func (d *DB) DisableBrought(ctx context.Context, id string) (bool, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE cas SET status = 'disabled', disabled_at = ?, meraki_key_enc = x'', meraki_key_nonce = x''
		WHERE id = ? AND status = 'active'`, millis(d.now()), id)
	if err != nil {
		return false, fmt.Errorf("disable ca %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// InsertBrought は持ち込みの CA と最初の CRL（crl が nil でなければ）を 1 つのトランザクションで入れる。
// 同じ ID か、同じフィンガープリントの有効な CA があれば ErrConflict。
func (d *DB) InsertBrought(ctx context.Context, c CA, crl *CRL) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if crl != nil {
			c.CRLNumber = 1
		}
		if err := insertCA(ctx, tx, c); err != nil {
			return err
		}
		if crl == nil {
			return nil
		}
		crl.CAID, crl.Number = c.ID, 1
		return insertCRL(ctx, tx, *crl)
	})
}

// CRLState は持ち込みの CA の CRL の取得の状態（§19.3）。
type CRLState struct {
	ETag, Modified  string
	CheckedAt, OKAt time.Time
	Failures        int
	LastError       string
}

// SetCRLState は取得の状態を書く。
func (d *DB) SetCRLState(ctx context.Context, id string, s CRLState) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE cas SET crl_etag = ?, crl_modified = ?, crl_checked_at = ?, crl_ok_at = ?, crl_failures = ?, crl_last_error = ? WHERE id = ?`,
		s.ETag, s.Modified, millis(s.CheckedAt), millis(s.OKAt), s.Failures, s.LastError, id)
	if err != nil {
		return fmt.Errorf("set crl state of %s: %w", id, err)
	}
	return nil
}

// CRLSourceChange は CRL の取得先の変更（§19.5）。
type CRLSourceChange struct {
	Source, URL, MerakiOrgID     string
	MerakiKeyEnc, MerakiKeyNonce []byte
	// NoCRLBy と NoCRLAt は CRL なしの了承（source が none のとき）。
	NoCRLBy string
	NoCRLAt time.Time
	State   CRLState
}

// ChangeCRLSource は取得先と取得の状態を書き換え、新しい CRL（crl が nil でなければ）を置く（1 つのトランザクション）。
func (d *DB) ChangeCRLSource(ctx context.Context, id string, ch CRLSourceChange, crl *CRL) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		enc, nonce := ch.MerakiKeyEnc, ch.MerakiKeyNonce
		if enc == nil {
			enc, nonce = []byte{}, []byte{}
		}
		res, err := tx.ExecContext(ctx, `UPDATE cas SET crl_source = ?, crl_url = ?, meraki_org_id = ?, meraki_key_enc = ?, meraki_key_nonce = ?,
			no_crl_by = ?, no_crl_at = ?, crl_etag = ?, crl_modified = ?, crl_checked_at = ?, crl_ok_at = ?, crl_failures = ?, crl_last_error = ? WHERE id = ?`,
			ch.Source, ch.URL, ch.MerakiOrgID, enc, nonce, ch.NoCRLBy, millis(ch.NoCRLAt), ch.State.ETag, ch.State.Modified,
			millis(ch.State.CheckedAt), millis(ch.State.OKAt), ch.State.Failures, ch.State.LastError, id)
		if err != nil {
			return fmt.Errorf("change crl source of %s: %w", id, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if crl == nil {
			return nil
		}
		return appendCRL(ctx, tx, id, *crl)
	})
}

// RekeyCA は CA の暗号化した鍵を入れ替える（KEK の入れ替え。tx の中で呼ぶ）。
func RekeyCA(ctx context.Context, tx *sql.Tx, id string, enc, nonce []byte, kekID string) error {
	_, err := tx.ExecContext(ctx, "UPDATE cas SET key_enc = ?, key_nonce = ?, kek_id = ? WHERE id = ?", enc, nonce, kekID, id)
	return err
}

// RekeyMerakiKey は持ち込みの CA の暗号化した API キーを入れ替える（KEK の入れ替え。tx の中で呼ぶ）。
func RekeyMerakiKey(ctx context.Context, tx *sql.Tx, id string, enc, nonce []byte, kekID string) error {
	_, err := tx.ExecContext(ctx, "UPDATE cas SET meraki_key_enc = ?, meraki_key_nonce = ?, kek_id = ? WHERE id = ?", enc, nonce, kekID, id)
	return err
}

// Tx はトランザクションの中で fn を実行する（KEK の入れ替えなど、複数の行をまとめて変えるとき）。
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error { return d.tx(ctx, fn) }
