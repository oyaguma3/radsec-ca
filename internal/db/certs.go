package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// プロファイル（§5.2）。
const (
	ProfileAPClient     = "ap-client"
	ProfileProbeClient  = "probe-client"
	ProfileTenantServer = "tenant-server"
)

// Cert は発行した証明書の記録。
type Cert struct {
	Serial       string
	CAID         string
	Profile      string
	Tenant       string
	AP           string
	Edge         string
	CN           string
	SANDNS       []string
	SANURI       string
	NotBefore    time.Time
	NotAfter     time.Time
	CertDER      []byte
	PubKeySHA256 string
	RevokedAt    time.Time
	RevokeReason string
	IssuedBy     string
	TraceID      string
	CreatedAt    time.Time
}

// Status は証明書の状態（revoked / expired / valid）。
func (c Cert) Status(now time.Time) string {
	switch {
	case !c.RevokedAt.IsZero():
		return "revoked"
	case !now.Before(c.NotAfter):
		return "expired"
	}
	return "valid"
}

const certColumns = `serial, ca_id, profile, tenant, ap, edge, cn, san_dns, san_uri, not_before, not_after, cert_der, pubkey_sha256,
	revoked_at, revoke_reason, issued_by, trace_id, created_at`

func scanCert(s interface{ Scan(...any) error }) (Cert, error) {
	var c Cert
	var dns string
	var nb, na, ra, ca int64
	if err := s.Scan(&c.Serial, &c.CAID, &c.Profile, &c.Tenant, &c.AP, &c.Edge, &c.CN, &dns, &c.SANURI, &nb, &na, &c.CertDER,
		&c.PubKeySHA256, &ra, &c.RevokeReason, &c.IssuedBy, &c.TraceID, &ca); err != nil {
		return Cert{}, err
	}
	if dns != "" {
		c.SANDNS = strings.Split(dns, ",")
	}
	c.NotBefore, c.NotAfter, c.RevokedAt, c.CreatedAt = fromMillis(nb), fromMillis(na), fromMillis(ra), fromMillis(ca)
	return c, nil
}

// InsertCert は発行した証明書を記録する。シリアル番号が重なれば ErrConflict。
func (d *DB) InsertCert(ctx context.Context, c Cert) error {
	_, err := d.sql.ExecContext(ctx, "INSERT INTO certs ("+certColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.Serial, c.CAID, c.Profile, c.Tenant, c.AP, c.Edge, c.CN, strings.Join(c.SANDNS, ","), c.SANURI,
		millis(c.NotBefore), millis(c.NotAfter), c.CertDER, c.PubKeySHA256, millis(c.RevokedAt), c.RevokeReason,
		c.IssuedBy, c.TraceID, millis(c.CreatedAt))
	if isUnique(err) {
		return fmt.Errorf("insert cert %s: %w", c.Serial, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("insert cert %s: %w", c.Serial, err)
	}
	return nil
}

// SerialExists はシリアル番号が使われているか。
func (d *DB) SerialExists(ctx context.Context, serial string) (bool, error) {
	var n int
	if err := d.sql.QueryRowContext(ctx, "SELECT count(*) FROM certs WHERE serial = ?", serial).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Cert はシリアル番号の証明書を返す。なければ ErrNotFound。
func (d *DB) Cert(ctx context.Context, serial string) (Cert, error) {
	c, err := scanCert(d.sql.QueryRowContext(ctx, "SELECT "+certColumns+" FROM certs WHERE serial = ?", serial))
	if errors.Is(err, sql.ErrNoRows) {
		return Cert{}, ErrNotFound
	}
	if err != nil {
		return Cert{}, fmt.Errorf("get cert %s: %w", serial, err)
	}
	return c, nil
}

// CertFilter は証明書の一覧の絞り込み。空の項目は絞り込まない。
type CertFilter struct {
	CAID, Tenant, Profile, AP, Edge string
	// Status は valid / revoked / expired。
	Status string
	// ExpiresBefore が非ゼロなら、その時刻より前に期限が切れるもの（失効したものを除く）。
	ExpiresBefore time.Time
	// After はページ送りの続き（前のページの最後の作成順の番号）。
	After int64
	Limit int
}

// CertPage は一覧の 1 ページ。Next は続きの After の値（なければ 0）。
type CertPage struct {
	Certs []Cert
	Next  int64
}

// Certs は絞り込んだ証明書を、新しく発行した順に返す。
func (d *DB) Certs(ctx context.Context, f CertFilter) (CertPage, error) {
	var where []string
	var args []any
	add := func(cond string, v ...any) {
		where = append(where, cond)
		args = append(args, v...)
	}
	now := millis(d.now())
	for _, c := range []struct{ col, v string }{{"ca_id", f.CAID}, {"tenant", f.Tenant}, {"profile", f.Profile}, {"ap", f.AP}, {"edge", f.Edge}} {
		if c.v != "" {
			add(c.col+" = ?", c.v)
		}
	}
	switch f.Status {
	case "":
	case "revoked":
		add("revoked_at != 0")
	case "expired":
		add("revoked_at = 0 AND not_after <= ?", now)
	case "valid":
		add("revoked_at = 0 AND not_after > ?", now)
	default:
		return CertPage{}, fmt.Errorf("list certs: unknown status %q", f.Status)
	}
	if !f.ExpiresBefore.IsZero() {
		add("revoked_at = 0 AND not_after < ?", millis(f.ExpiresBefore))
	}
	if f.After > 0 {
		add("rowid < ?", f.After)
	}
	q := "SELECT rowid, " + certColumns + " FROM certs"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	q += " ORDER BY rowid DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return CertPage{}, fmt.Errorf("list certs: %w", err)
	}
	defer rows.Close()
	var page CertPage
	var ids []int64
	for rows.Next() {
		var id int64
		var c Cert
		var dns string
		var nb, na, ra, ca int64
		if err := rows.Scan(&id, &c.Serial, &c.CAID, &c.Profile, &c.Tenant, &c.AP, &c.Edge, &c.CN, &dns, &c.SANURI, &nb, &na, &c.CertDER,
			&c.PubKeySHA256, &ra, &c.RevokeReason, &c.IssuedBy, &c.TraceID, &ca); err != nil {
			return CertPage{}, fmt.Errorf("list certs: %w", err)
		}
		if dns != "" {
			c.SANDNS = strings.Split(dns, ",")
		}
		c.NotBefore, c.NotAfter, c.RevokedAt, c.CreatedAt = fromMillis(nb), fromMillis(na), fromMillis(ra), fromMillis(ca)
		page.Certs = append(page.Certs, c)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return CertPage{}, err
	}
	if len(page.Certs) > limit {
		page.Certs = page.Certs[:limit]
		page.Next = ids[limit-1]
	}
	return page, nil
}

// CountCerts は、CA ごとの発行した証明書の数と、期限が before より前の有効な証明書の数を返す。
func (d *DB) CountCerts(ctx context.Context, before time.Time) (issued map[string]int, expiring int, err error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT ca_id, count(*) FROM certs GROUP BY ca_id")
	if err != nil {
		return nil, 0, fmt.Errorf("count certs: %w", err)
	}
	defer rows.Close()
	issued = map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, 0, err
		}
		issued[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	err = d.sql.QueryRowContext(ctx, "SELECT count(*) FROM certs WHERE revoked_at = 0 AND not_after > ? AND not_after < ?",
		millis(d.now()), millis(before)).Scan(&expiring)
	return issued, expiring, err
}
