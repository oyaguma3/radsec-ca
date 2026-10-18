package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CA の種類と状態（§5.1）。
const (
	KindServer       = "server"
	KindTenantClient = "tenant-client"

	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// CA は CA の記録。KeyEnc は暗号化した秘密鍵（復号は internal/kek）。
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
}

const caColumns = "id, kind, tenant, cert_der, key_enc, key_nonce, kek_id, status, crl_number, not_after, created_at, disabled_at"

func scanCA(s interface{ Scan(...any) error }) (CA, error) {
	var c CA
	var na, ca, da int64
	if err := s.Scan(&c.ID, &c.Kind, &c.Tenant, &c.CertDER, &c.KeyEnc, &c.KeyNonce, &c.KEKID, &c.Status, &c.CRLNumber, &na, &ca, &da); err != nil {
		return CA{}, err
	}
	c.NotAfter, c.CreatedAt, c.DisabledAt = fromMillis(na), fromMillis(ca), fromMillis(da)
	return c, nil
}

// InsertCA は CA を入れる。同じ ID があれば ErrConflict。
func (d *DB) InsertCA(ctx context.Context, c CA) error {
	_, err := d.sql.ExecContext(ctx, "INSERT INTO cas ("+caColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.Kind, c.Tenant, c.CertDER, c.KeyEnc, c.KeyNonce, c.KEKID, c.Status, c.CRLNumber,
		millis(c.NotAfter), millis(c.CreatedAt), millis(c.DisabledAt))
	if isUnique(err) {
		return fmt.Errorf("insert ca %s: %w", c.ID, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("insert ca %s: %w", c.ID, err)
	}
	return nil
}

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

// CAs はすべての CA を ID の順に返す（server が先頭）。
func (d *DB) CAs(ctx context.Context) ([]CA, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT "+caColumns+" FROM cas ORDER BY kind = 'tenant-client', id")
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

// RekeyCA は CA の暗号化した鍵を入れ替える（KEK の入れ替え。tx の中で呼ぶ）。
func RekeyCA(ctx context.Context, tx *sql.Tx, id string, enc, nonce []byte, kekID string) error {
	_, err := tx.ExecContext(ctx, "UPDATE cas SET key_enc = ?, key_nonce = ?, kek_id = ? WHERE id = ?", enc, nonce, kekID, id)
	return err
}

// Tx はトランザクションの中で fn を実行する（KEK の入れ替えなど、複数の行をまとめて変えるとき）。
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error { return d.tx(ctx, fn) }
