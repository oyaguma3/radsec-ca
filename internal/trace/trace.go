// Package trace はトレースID を扱う。
//
// 本CA は画面の要求ごとにトレースID を採番し、管理API では X-Trace-ID を受け取って（なければ採番して）、
// アクセスログと監査ログに残す（本書 §9.1、§13）。
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type key struct{}

// New はトレースID（16進32桁。provisioner が自分で採番する形式と同じ）を作る。
func New() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// With はトレースID をコンテキストに入れる。
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, key{}, id)
}

// From はコンテキストに入れたトレースID を返す。入っていなければ空文字列。
func From(ctx context.Context) string {
	id, _ := ctx.Value(key{}).(string)
	return id
}
