package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/certs"
)

const shutdownTimeout = 10 * time.Second

// ListenOptions は管理API のリスナーの設定。
type ListenOptions struct {
	Addr string
	// GetCertificate はサーバー証明書を返す。
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// AdminClients は管理クライアントの証明書のフィンガープリント（SHA-256、16 進小文字）から識別名を引く。
	AdminClients map[string]string
	Handler      http.Handler
	Log          *slog.Logger
}

// Run は管理API の HTTPS リスナー（mTLS）を起動し、ctx が終了するかリスナーが失敗するまで待つ（eapaka-node-provisioner の
// internal/server と同じ作り）。管理クライアントは、クライアント証明書のフィンガープリントで照合する（CA は使わない。§9.1）。
// 証明書なし・未登録・有効期間外の接続は、TLS のハンドシェイクで断る。
func Run(ctx context.Context, opts ListenOptions) error {
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", opts.Addr, err)
	}
	return Serve(ctx, ln, opts)
}

// Serve は ln で待ち受ける（opts.Addr は使わない）。
func Serve(ctx context.Context, ln net.Listener, opts ListenOptions) error {
	srv := &http.Server{
		Handler:           opts.Handler,
		TLSConfig:         TLSConfig(opts),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(opts.Log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	opts.Log.Info("listening", "addr", ln.Addr().String(), "admin_clients", len(opts.AdminClients))
	select {
	case <-ctx.Done():
		opts.Log.Info("shutting down")
	case err := <-errc:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		opts.Log.Warn("shutdown", "error", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// TLSConfig は、管理クライアントの証明書をフィンガープリントで照合する TLS 設定を返す。
func TLSConfig(opts ListenOptions) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: opts.GetCertificate,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("client certificate required")
			}
			cert := cs.PeerCertificates[0]
			fp := certs.Fingerprint(cert)
			if _, ok := opts.AdminClients[fp]; !ok {
				opts.Log.Warn("admin client certificate rejected", "event_id", "CA_AUTH_REJECTED", "reason", "not configured", "fingerprint", fp)
				return errors.New("client certificate is not a configured admin client")
			}
			if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				opts.Log.Warn("admin client certificate rejected", "event_id", "CA_AUTH_REJECTED", "reason", "outside validity period", "fingerprint", fp)
				return errors.New("client certificate is outside its validity period")
			}
			return nil
		},
	}
}

// AdminClientName は、要求を送ってきた管理クライアントの識別名を返す。mTLS でなければ空文字列。
func AdminClientName(r *http.Request, clients map[string]string) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return clients[certs.Fingerprint(r.TLS.PeerCertificates[0])]
}
