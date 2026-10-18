package db

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
)

// 監査ログの出どころ（AuditEntry.Source）。
const (
	SourceGUI    = "gui"
	SourceAPI    = "api"
	SourceCLI    = "cli"
	SourceSystem = "system"
)

// AuditEntry は監査ログの 1 件（§13）。Detail に鍵・KEK・CSR と証明書の本体を入れてはならない。
type AuditEntry struct {
	ID int64
	// Time は書き込むときに DB が決める（読み出しで入る）。
	Time time.Time
	// Operator は画面の利用者のメールアドレス、または X-Operator-Id。MgmtClient は管理API の管理クライアントの識別名。
	Operator   string
	MgmtClient string
	Source     string
	Action     string
	Target     string
	// Result は ok か、失敗の理由の符号。
	Result  string
	Detail  map[string]any
	TraceID string
}

// InsertAudit は監査ログを 1 件書き込む。
func (d *DB) InsertAudit(ctx context.Context, e AuditEntry) error {
	detail := []byte("{}")
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail, json.Deterministic(true))
		if err != nil {
			return fmt.Errorf("insert audit: encode detail: %w", err)
		}
		detail = b
	}
	if e.Result == "" {
		e.Result = "ok"
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO audit (time, operator, mgmt_client, source, action, target, trace_id, result, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, millis(d.now()), e.Operator, e.MgmtClient, e.Source, e.Action, e.Target, e.TraceID, e.Result, string(detail))
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

// ListAudit は監査ログを新しい順に返す。before が 0 でなければ、その ID より古いものだけ。
func (d *DB) ListAudit(ctx context.Context, before int64, limit int) ([]AuditEntry, error) {
	q := "SELECT id, time, operator, mgmt_client, source, action, target, trace_id, result, details FROM audit"
	args := []any{}
	if before > 0 {
		q += " WHERE id < ?"
		args = append(args, before)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var t int64
		var detail string
		if err := rows.Scan(&e.ID, &t, &e.Operator, &e.MgmtClient, &e.Source, &e.Action, &e.Target, &e.TraceID, &e.Result, &detail); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.Time = fromMillis(t)
		if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
			return nil, fmt.Errorf("list audit: decode detail of %d: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
