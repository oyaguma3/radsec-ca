// radsec-ca は radsec-edge のための独立した CA（設計概要 §1）。
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	// distroless のイメージにはタイムゾーンのデータがないので、埋め込んで環境変数 TZ を効かせる。
	_ "time/tzdata"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/certs"
	"github.com/oyaguma3/radsec-ca/internal/config"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/server"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: radsec-ca <command>

commands:
  serve        サーバーを起動する（コマンド省略時の既定）。初めてなら DB とサーバーCA を作る
  migrate      DB のスキーマを移行して終わる
  gen-kek      KEK（CA の鍵を暗号化する鍵）のファイルを作る（radsec-ca gen-kek -out <ファイル>）
  server-cert  管理API のサーバー証明書（なければ作る）を標準出力に、フィンガープリントを標準エラーに出す
  healthcheck  動いている radsec-ca を確かめる（compose の healthcheck 用）

設定は環境変数（接頭辞 CA_）で与える。
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"serve"}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "serve":
		err = serve(ctx)
	case "migrate":
		err = migrate(ctx)
	case "gen-kek":
		err = genKEK(args[1:], os.Stderr)
	case "server-cert":
		err = serverCert(os.Stdout, os.Stderr)
	case "healthcheck":
		err = healthcheck(ctx)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newLogger(cfg config.Config) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
}

// openDB は DB を開いてスキーマを移行する（DB のディレクトリがなければ作る）。
func openDB(ctx context.Context, cfg config.Config, log *slog.Logger) (*db.DB, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		return nil, err
	}
	d, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}
	applied, err := d.Migrate(ctx)
	if err != nil {
		d.Close()
		return nil, err
	}
	v, err := d.SchemaVersion(ctx)
	if err != nil {
		d.Close()
		return nil, err
	}
	log.Info("database", "file", cfg.DBPath, "schema_version", v, "applied", applied)
	return d, nil
}

// app は起動した本CA の部品。
type app struct {
	cfg    config.Config
	log    *slog.Logger
	db     *db.DB
	signer *signer.Local
	ca     *ca.Service
}

// start は設定を読み、DB を開き、起動のときの確認（KEK と CA の鍵。§6.2）を行い、サーバーCA がなければ作る。
func start(ctx context.Context) (*app, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	log := newLogger(cfg)
	log.Info("starting", "event_id", "CA_STARTED", "version", version, "org", cfg.Org, "urn_prefix", cfg.URNPrefix, "dns_domain", cfg.DNSDomain)
	k, err := kek.Load(cfg.KEKFile)
	if err != nil {
		return nil, err
	}
	d, err := openDB(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	sig := &signer.Local{DB: d, KEK: k}
	n, err := sig.Check(ctx)
	if err != nil {
		if errors.Is(err, signer.ErrKEKMismatch) {
			log.Error("the KEK does not match the database", "event_id", "CA_KEK_MISMATCH", "kek_id", k.ID(), "error", err)
		}
		d.Close()
		return nil, err
	}
	log.Info("kek", "kek_id", k.ID(), "cas_checked", n)
	svc := ca.New(ca.Options{Log: log, DB: d, Signer: sig, Org: cfg.Org, URNPrefix: cfg.URNPrefix, DNSDomain: cfg.DNSDomain,
		APCertDays: cfg.APCertDays, ServerCertDays: cfg.ServerCertDays, CRLValidity: cfg.CRLValidity, CRLRefresh: cfg.CRLRefresh})
	created, err := svc.Init(ctx)
	if err != nil {
		d.Close()
		return nil, err
	}
	if created {
		log.Info("created the server CA", "ca", signer.ServerCAID)
	}
	return &app{cfg: cfg, log: log, db: d, signer: sig, ca: svc}, nil
}

func serve(ctx context.Context) error {
	a, err := start(ctx)
	if err != nil {
		return err
	}
	defer a.db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.db.Ping(r.Context()); err != nil {
			http.Error(w, "db is not available", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return server.Run(ctx, server.Options{Addr: a.cfg.GUIAddr, Handler: mux, Log: a.log})
}

func migrate(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	d, err := openDB(ctx, cfg, newLogger(cfg))
	if err != nil {
		return err
	}
	return d.Close()
}

const genKEKUsage = `usage: radsec-ca gen-kek -out <ファイル>

CA の鍵を暗号化する鍵（KEK。32 バイトの乱数を 16 進で書いたもの）のファイルを作る（権限 600）。
既存のファイルは上書きしない。KEK は DB とは別の場所に、オフラインでも保管する（失うと、すべての CA を作り直すことになる）。

options:
`

func genKEK(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("gen-kek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, genKEKUsage)
		fs.PrintDefaults()
	}
	out := fs.String("out", "", "KEK のファイル")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *out == "" || fs.NArg() > 0 {
		fs.Usage()
		return errors.New("-out is required")
	}
	k, err := kek.Generate(*out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "KEK を作りました: %s（識別子 %s）。DB とは別の場所にも保管してください。\n", *out, k.ID())
	return nil
}

// serverCert は管理API のサーバー証明書（なければ作る）を出す。provisioner にはこの証明書を検証用として渡す（§9.1）。
func serverCert(stdout, stderr io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	certPath, keyPath := filepath.Join(cfg.TLSDir, "server.pem"), filepath.Join(cfg.TLSDir, "server.key")
	created, err := certs.EnsureFiles(certPath, keyPath, cfg.TLSHosts)
	if err != nil {
		return err
	}
	f, err := certs.LoadFile(certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	stdout.Write(b)
	if created {
		fmt.Fprintf(stderr, "サーバー証明書を作りました（SAN: %v）。\n", cfg.TLSHosts)
	}
	fmt.Fprintf(stderr, "SHA-256 フィンガープリント: %s（有効期限 %s）\n", certs.Fingerprint(f.Leaf()), f.Leaf().NotAfter.Local().Format(time.DateOnly))
	return nil
}

// healthcheck は、同じコンテナで動いている本CA の /healthz を確かめる（distroless のイメージには curl がないため）。
func healthcheck(ctx context.Context) error {
	_, port, err := net.SplitHostPort(cmp.Or(os.Getenv("CA_GUI_ADDR"), ":8448"))
	if err != nil {
		return fmt.Errorf("CA_GUI_ADDR: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}
