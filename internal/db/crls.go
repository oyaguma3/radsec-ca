package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// keepCRLs は CA ごとに残す CRL の数（§7.2）。
const keepCRLs = 30

// CRL は作った CRL。
type CRL struct {
	CAID string
	// Number は CA ごとのこちらの連番。ExtNumber は持ち込みの CRL の cRLNumber（10 進の文字列。なければ空。§19.3）。
	Number                 int64
	ExtNumber              string
	ThisUpdate, NextUpdate time.Time
	DER                    []byte
	CreatedAt              time.Time
}

// Revoked は CRL に載せる失効した証明書。
type Revoked struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    string
}

// RevokedForCRL は、CA caID が発行して失効させた証明書のうち、有効期限が now より後のもの（CRL に載せるもの。§7.2）を返す。
func (d *DB) RevokedForCRL(ctx context.Context, caID string, now time.Time) ([]Revoked, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT serial, revoked_at, revoke_reason FROM certs
		WHERE ca_id = ? AND revoked_at != 0 AND not_after > ? ORDER BY revoked_at`, caID, millis(now))
	if err != nil {
		return nil, fmt.Errorf("revoked certs: %w", err)
	}
	defer rows.Close()
	var out []Revoked
	for rows.Next() {
		var serial, reason string
		var at int64
		if err := rows.Scan(&serial, &at, &reason); err != nil {
			return nil, err
		}
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			return nil, fmt.Errorf("revoked certs: bad serial %q", serial)
		}
		out = append(out, Revoked{Serial: n, RevokedAt: fromMillis(at), Reason: reason})
	}
	return out, rows.Err()
}

// NextCRLNumber は、CA caID の次の CRL の番号（今の番号 + 1）を返す。
func (d *DB) NextCRLNumber(ctx context.Context, caID string) (int64, error) {
	var n int64
	err := d.sql.QueryRowContext(ctx, "SELECT crl_number FROM cas WHERE id = ?", caID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n + 1, err
}

// InsertCRL は CRL を記録し、CA の CRL の番号を進め、古い CRL を消す（1 つのトランザクション）。
// 番号が CA の今の番号 + 1 でなければ ErrConflict（作り直しが重なった）。
func (d *DB) InsertCRL(ctx context.Context, c CRL) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE cas SET crl_number = ? WHERE id = ? AND crl_number = ?", c.Number, c.CAID, c.Number-1)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("insert crl %s #%d: %w", c.CAID, c.Number, ErrConflict)
		}
		return insertCRL(ctx, tx, c)
	})
}

// insertCRL は CRL の行を入れ、古い CRL を消す（tx の中で呼ぶ）。
func insertCRL(ctx context.Context, tx *sql.Tx, c CRL) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO crls (ca_id, number, this_update, next_update, der, created_at, ext_number) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.CAID, c.Number, millis(c.ThisUpdate), millis(c.NextUpdate), c.DER, millis(c.CreatedAt), c.ExtNumber); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM crls WHERE ca_id = ? AND number <= ?", c.CAID, c.Number-keepCRLs)
	return err
}

// appendCRL は CA の連番を 1 つ進めて CRL を置く（持ち込みの CA。tx の中で呼ぶ）。
func appendCRL(ctx context.Context, tx *sql.Tx, id string, c CRL) error {
	var n int64
	if err := tx.QueryRowContext(ctx, "UPDATE cas SET crl_number = crl_number + 1 WHERE id = ? RETURNING crl_number", id).Scan(&n); err != nil {
		return fmt.Errorf("append crl %s: %w", id, err)
	}
	c.CAID, c.Number = id, n
	return insertCRL(ctx, tx, c)
}

// PutBroughtCRL は持ち込みの CA の新しい CRL を置き、取得の状態を書く（1 つのトランザクション）。
func (d *DB) PutBroughtCRL(ctx context.Context, id string, c CRL, s CRLState) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if err := appendCRL(ctx, tx, id, c); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE cas SET crl_etag = ?, crl_modified = ?, crl_checked_at = ?, crl_ok_at = ?, crl_failures = ?, crl_last_error = ? WHERE id = ?`,
			s.ETag, s.Modified, millis(s.CheckedAt), millis(s.OKAt), s.Failures, s.LastError, id)
		return err
	})
}

const crlColumns = "ca_id, number, this_update, next_update, der, created_at, ext_number"

func scanCRL(s interface{ Scan(...any) error }) (CRL, error) {
	var c CRL
	var tu, nu, ca int64
	if err := s.Scan(&c.CAID, &c.Number, &tu, &nu, &c.DER, &ca, &c.ExtNumber); err != nil {
		return CRL{}, err
	}
	c.ThisUpdate, c.NextUpdate, c.CreatedAt = fromMillis(tu), fromMillis(nu), fromMillis(ca)
	return c, nil
}

// LatestCRL は CA caID の最新の CRL を返す。なければ ErrNotFound。
func (d *DB) LatestCRL(ctx context.Context, caID string) (CRL, error) {
	c, err := scanCRL(d.sql.QueryRowContext(ctx, "SELECT "+crlColumns+" FROM crls WHERE ca_id = ? ORDER BY number DESC LIMIT 1", caID))
	if errors.Is(err, sql.ErrNoRows) {
		return CRL{}, ErrNotFound
	}
	if err != nil {
		return CRL{}, fmt.Errorf("latest crl %s: %w", caID, err)
	}
	return c, nil
}

// CRLs は CA caID の CRL を新しい順に返す（中身の DER も含む）。
func (d *DB) CRLs(ctx context.Context, caID string) ([]CRL, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT "+crlColumns+" FROM crls WHERE ca_id = ? ORDER BY number DESC", caID)
	if err != nil {
		return nil, fmt.Errorf("list crls %s: %w", caID, err)
	}
	defer rows.Close()
	var out []CRL
	for rows.Next() {
		c, err := scanCRL(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
