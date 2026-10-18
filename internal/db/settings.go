package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// 設定の値の名前。
const (
	// SettingKEKID は KEK の識別子（KEK の SHA-256 の先頭 8 バイトの 16 進。§6.1）。
	SettingKEKID = "kek_id"
)

// Setting は設定の値を返す。なければ "" と false。
func (d *DB) Setting(ctx context.Context, name string) (string, bool, error) {
	return setting(ctx, d.sql, name)
}

func setting(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, "SELECT value FROM settings WHERE name = ?", name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get setting %s: %w", name, err)
	}
	return v, true, nil
}

// SetSetting は設定の値を書く。
func (d *DB) SetSetting(ctx context.Context, name, value string) error {
	return SetSettingTx(ctx, d.sql, name, value)
}

// SetSettingTx は設定の値を書く（トランザクションの中でも使える）。
func SetSettingTx(ctx context.Context, e interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, name, value string) error {
	_, err := e.ExecContext(ctx, "INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value", name, value)
	if err != nil {
		return fmt.Errorf("set setting %s: %w", name, err)
	}
	return nil
}
