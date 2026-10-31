// Package web は本CA の運用者向けの画面（Go + htmx + daisyUI。設計概要 §10）。radsec-edge の画面の土台
// （eapaka-ossbss-sample をコピーして手直ししたもの）をコピーした。
//
// 同梱しているサードパーティのファイル（static/）:
//   - htmx.min.js: htmx 2.0.11（https://htmx.org、0BSD）
//   - app.css: Tailwind CSS（MIT）と daisyUI（MIT）で生成する。リポジトリには入れず、scripts/build-css.sh で作る。
package web

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/auth"
	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/db"
)

//go:embed templates static
var assets embed.FS

// Handler は画面のハンドラー。
type Handler struct {
	Options
	pages  pages
	static *staticFiles
}

// Options は Handler の設定。
type Options struct {
	Log *slog.Logger
	// Version は画面のフッターに出すバージョン、KEKID はダッシュボードに出す KEK の識別子。
	Version, KEKID string
	DB             *db.DB
	CA             *ca.Service
	Identifier     auth.Identifier
	// InitialAdmin は最初の管理者のメールアドレス（画面からの降格・無効化を断る）。
	InitialAdmin string
	// APIEnabled は管理API を待ち受けているか（管理モード。署名と失効の画面に注意を出す。§10.2）。
	APIEnabled bool
	// Now は現在時刻（テストで差し替える）。
	Now func() time.Time
}

// New は Handler を作る。
func New(o Options) (*Handler, error) {
	if o.Identifier == nil || o.CA == nil || o.DB == nil {
		return nil, fmt.Errorf("web: identifier, ca and db are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	h := &Handler{Options: o}
	var err error
	if h.pages, err = parsePages(); err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	if h.static, err = newStaticFiles(http.HandlerFunc(h.notFound)); err != nil {
		return nil, fmt.Errorf("load static files: %w", err)
	}
	return h, nil
}

// Routes はルーティングとミドルウェアを組み立てた http.Handler を返す。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", h.static)
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /{$}", h.home)

	mux.HandleFunc("POST /cas", h.requireAdmin(h.caCreate))
	mux.HandleFunc("GET /cas/{id}", h.caDetail)
	mux.HandleFunc("GET /cas/{id}/ca.pem", h.caDownload)
	mux.HandleFunc("GET /cas/{id}/crls/{number}", h.crlDownload)
	mux.HandleFunc("POST /cas/{id}/disable", h.requireAdmin(h.caDisable))
	mux.HandleFunc("POST /cas/{id}/crl/refresh", h.requireAdmin(h.crlRefresh))
	mux.HandleFunc("POST /cas/{id}/crl/upload", h.requireAdmin(h.crlUpload))

	mux.HandleFunc("GET /certs", h.certList)
	mux.HandleFunc("GET /certs/{serial}", h.certDetail)
	mux.HandleFunc("GET /certs/{serial}/cert.pem", h.certDownload)
	mux.HandleFunc("POST /certs/{serial}/revoke", h.requireAdmin(h.certRevoke))

	mux.HandleFunc("GET /sign", h.requireAdmin(h.signForm))
	mux.HandleFunc("POST /sign", h.requireAdmin(h.sign))

	mux.HandleFunc("GET /users", h.requireAdmin(h.userList))
	mux.HandleFunc("POST /users", h.requireAdmin(h.userCreate))
	mux.HandleFunc("POST /users/{email}/update", h.requireAdmin(h.userUpdate))

	mux.HandleFunc("GET /audit", h.audit)
	mux.HandleFunc("/", h.notFound)

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Log.Warn("cross-origin request rejected", "method", r.Method, "path", r.URL.Path, "origin", r.Header.Get("Origin"))
		h.renderError(w, r, http.StatusForbidden, "この操作は受け付けられません。画面を開き直してから操作してください。")
	}))
	return h.accessLog(securityHeaders(cop.Handler(h.authenticate(mux))))
}

// healthz は DB を使えれば 200 を返す（compose の healthcheck に使う。認証の対象外）。
func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.DB.Ping(ctx); err != nil {
		h.Log.Warn("healthz: db is not available", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "db is not available")
		return
	}
	fmt.Fprintln(w, "ok")
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusNotFound, "ページが見つかりません。")
}

// readForm はフォームを読む（大きさの上限つき）。
func readForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	return r.ParseForm()
}

// download はファイルとして返す。
func download(w http.ResponseWriter, name, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}
