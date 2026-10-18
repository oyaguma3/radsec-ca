package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// 利用者の役割（§10.1）。
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// User は画面の利用者。
type User struct {
	Email     string
	Role      string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func scanUser(s interface{ Scan(...any) error }) (User, error) {
	var u User
	var c, up int64
	if err := s.Scan(&u.Email, &u.Role, &u.Enabled, &c, &up); err != nil {
		return User{}, err
	}
	u.CreatedAt, u.UpdatedAt = fromMillis(c), fromMillis(up)
	return u, nil
}

// User はメールアドレスの利用者を返す。なければ ErrNotFound。
func (d *DB) User(ctx context.Context, email string) (User, error) {
	u, err := scanUser(d.sql.QueryRowContext(ctx, "SELECT email, role, enabled, created_at, updated_at FROM users WHERE email = ?", email))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// Users はすべての利用者をメールアドレスの順に返す。
func (d *DB) Users(ctx context.Context) ([]User, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT email, role, enabled, created_at, updated_at FROM users ORDER BY email")
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateUser は利用者を作る。あれば ErrConflict。
func (d *DB) CreateUser(ctx context.Context, email, role string) error {
	now := millis(d.now())
	_, err := d.sql.ExecContext(ctx, "INSERT INTO users (email, role, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)", email, role, now, now)
	if isUnique(err) {
		return fmt.Errorf("create user: %w", ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// UpdateUser は利用者の役割と有効・無効を変える。なければ ErrNotFound。
func (d *DB) UpdateUser(ctx context.Context, email, role string, enabled bool) error {
	res, err := d.sql.ExecContext(ctx, "UPDATE users SET role = ?, enabled = ?, updated_at = ? WHERE email = ?", role, enabled, millis(d.now()), email)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnsureInitialAdmin は、最初の管理者を admin・有効にする（なければ作る）。締め出されたときに戻す経路（§10.1）。
// 作った・戻したときは true を返す。
func (d *DB) EnsureInitialAdmin(ctx context.Context, email string) (bool, error) {
	u, err := d.User(ctx, email)
	switch {
	case errors.Is(err, ErrNotFound):
		return true, d.CreateUser(ctx, email, RoleAdmin)
	case err != nil:
		return false, err
	case u.Role == RoleAdmin && u.Enabled:
		return false, nil
	}
	return true, d.UpdateUser(ctx, email, RoleAdmin, true)
}
