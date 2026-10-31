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

	"github.com/oyaguma3/radsec-ca/internal/access"
	"github.com/oyaguma3/radsec-ca/internal/api"
	"github.com/oyaguma3/radsec-ca/internal/audit"
	"github.com/oyaguma3/radsec-ca/internal/auth"
	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/certs"
	"github.com/oyaguma3/radsec-ca/internal/config"
	"github.com/oyaguma3/radsec-ca/internal/crlfetch"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/publish"
	"github.com/oyaguma3/radsec-ca/internal/server"
	"github.com/oyaguma3/radsec-ca/internal/signer"
	"github.com/oyaguma3/radsec-ca/internal/web"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: radsec-ca <command>

commands:
  serve        サーバーを起動する（コマンド省略時の既定）。初めてなら DB とサーバーCA を作る
  migrate      DB のスキーマを移行して終わる
  gen-kek      KEK（CA の鍵を暗号化する鍵）のファイルを作る（radsec-ca gen-kek -out <ファイル>）
  rotate-kek   すべての CA の鍵を新しい KEK で暗号化し直す（radsec-ca rotate-kek -old <ファイル> -new <ファイル>。止めてから行う）
  backup       動かしたまま DB の写しを作る（radsec-ca backup -out <ファイル>）
  server-cert  管理API のサーバー証明書（なければ作る）を標準出力に、フィンガープリントを標準エラーに出す
  replace-server-cert  管理API のサーバー証明書を作り直して標準出力に出す（動いているサーバーは SIGHUP で読み直す）
  healthcheck  動いている radsec-ca を確かめる（compose の healthcheck 用）

設定は環境変数（接頭辞 CA_）で与える。管理クライアントのピンとサーバー証明書は SIGHUP で読み直す。
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
	case "rotate-kek":
		err = rotateKEK(ctx, args[1:], os.Stderr)
	case "backup":
		err = backup(ctx, args[1:], os.Stderr)
	case "server-cert":
		err = serverCert(os.Stdout, os.Stderr)
	case "replace-server-cert":
		err = replaceServerCert(ctx, os.Stdout, os.Stderr)
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
	d.SetAuditSink(audit.NewFiles(cfg.AuditDir, cfg.AuditRetentionDays))
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
	if err := audit.CheckWritableDir(cfg.AuditDir); err != nil {
		log.Error("cannot write audit files", "event_id", "CA_AUDIT_DIR_ERR", "dir", cfg.AuditDir, "error", err)
		return nil, err
	}
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
	fetcher, err := crlfetch.New(crlfetch.Options{Timeout: cfg.BroughtCRLTimeout, AllowPrivate: cfg.BroughtCRLAllowPrivate, MerakiBase: cfg.MerakiAPIBase})
	if err != nil {
		d.Close()
		return nil, fmt.Errorf("CA_MERAKI_API_BASE: %w", err)
	}
	if cfg.BroughtCRLAllowPrivate {
		log.Warn("the CRL source may be an internal address (CA_BROUGHT_CRL_ALLOW_PRIVATE). Do not use this setting in production")
	}
	svc := ca.New(ca.Options{Log: log, DB: d, Signer: sig, Org: cfg.Org, URNPrefix: cfg.URNPrefix, DNSDomain: cfg.DNSDomain,
		APCertDays: cfg.APCertDays, GroupCertDays: cfg.GroupCertDays, ServerCertDays: cfg.ServerCertDays,
		CRLValidity: cfg.CRLValidity, CRLRefresh: cfg.CRLRefresh, Fetcher: fetcher, BroughtCRLRefresh: cfg.BroughtCRLRefresh, Secrets: sig})
	created, err := svc.Init(ctx)
	if err != nil {
		d.Close()
		return nil, err
	}
	if created {
		log.Info("created the server CA", "ca", signer.ServerCAID)
	}
	// 最初の管理者（§10.1）。役割を変えられていたり無効にされていたりしたら戻す（締め出されたときに戻す経路）。
	if changed, err := d.EnsureInitialAdmin(ctx, cfg.InitialAdminEmail); err != nil {
		d.Close()
		return nil, err
	} else if changed {
		log.Warn("the initial admin was created or restored to an enabled admin", "email", cfg.InitialAdminEmail)
	}
	return &app{cfg: cfg, log: log, db: d, signer: sig, ca: svc}, nil
}

func serve(ctx context.Context) error {
	a, err := start(ctx)
	if err != nil {
		return err
	}
	defer a.db.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.ca.Run(ctx)
	go maintainAudit(ctx, a.log, audit.NewFiles(a.cfg.AuditDir, a.cfg.AuditRetentionDays))

	ident, err := newIdentifier(ctx, a.cfg, a.log)
	if err != nil {
		return err
	}
	gui, err := web.New(web.Options{Log: a.log.With("listener", "gui"), Version: version, KEKID: a.signer.KEK.ID(), DB: a.db, CA: a.ca,
		Identifier: ident, InitialAdmin: a.cfg.InitialAdminEmail, APIEnabled: a.cfg.APIEnabled()})
	if err != nil {
		return err
	}
	runs := []func(context.Context) error{
		func(ctx context.Context) error {
			return server.Run(ctx, server.Options{Addr: a.cfg.GUIAddr, Handler: gui.Routes(), Log: a.log.With("listener", "gui")})
		},
		func(ctx context.Context) error {
			h := &publish.Handler{Log: a.log, DB: a.db}
			return server.Run(ctx, server.Options{Addr: a.cfg.PublishAddr, Handler: h.Routes(), Log: a.log.With("listener", "publish")})
		},
	}
	if a.cfg.APIEnabled() {
		run, reload, err := a.apiRunner()
		if err != nil {
			return err
		}
		runs = append(runs, run)
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					reload()
				}
			}
		}()
	} else {
		a.log.Info("the management API is disabled (no admin clients file)", "file", a.cfg.AdminClientsFile)
	}
	return runAll(ctx, cancel, runs...)
}

// maintainAudit は監査ログのファイルを、起動のときと 1 時間ごとに整理する（圧縮と、保存の日数を過ぎたものの削除）。
func maintainAudit(ctx context.Context, log *slog.Logger, f *audit.Files) {
	for {
		if err := f.Maintain(time.Now()); err != nil {
			log.Error("cannot maintain audit files", "event_id", "CA_AUDIT_FILE_ERR", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// apiRunner は管理API（mTLS）のリスナーと、SIGHUP で動かす読み直しを用意する。サーバー証明書がなければ自己署名で作る（§9.1）。
func (a *app) apiRunner() (func(context.Context) error, func(), error) {
	pins, err := api.LoadPins(a.cfg.AdminClientsFile)
	if err != nil {
		return nil, nil, fmt.Errorf("admin clients: %w", err)
	}
	certPath, keyPath := filepath.Join(a.cfg.TLSDir, "server.pem"), filepath.Join(a.cfg.TLSDir, "server.key")
	if created, err := certs.EnsureFiles(certPath, keyPath, a.cfg.TLSHosts); err != nil {
		return nil, nil, err
	} else if created {
		a.log.Info("created a self-signed server certificate for the management API", "hosts", a.cfg.TLSHosts)
	}
	f, err := certs.LoadFile(certPath, keyPath, a.log)
	if err != nil {
		return nil, nil, err
	}
	a.log.Info("management API", "fingerprint", certs.Fingerprint(f.Leaf()), "not_after", f.Leaf().NotAfter, "admin_clients", pins.Names())
	h := &api.Handler{Log: a.log.With("listener", "api"), DB: a.db, CA: a.ca, Version: version, KEKID: a.signer.KEK.ID(), MgmtClient: pins.NameFromRequest}
	run := func(ctx context.Context) error {
		return api.Run(ctx, api.ListenOptions{Addr: a.cfg.APIAddr, GetCertificate: f.GetCertificate, Pins: pins,
			Handler: h.Routes(), Log: a.log.With("listener", "api")})
	}
	// 読み直しは、それぞれ失敗したら前のまま続ける。
	reload := func() {
		if err := pins.Reload(); err != nil {
			a.log.Error("failed to reload admin clients (keeping the previous ones)", "event_id", "CA_ADMIN_CLIENTS_RELOAD_ERR", "error", err.Error())
		} else {
			a.log.Info("reloaded admin clients", "event_id", "CA_ADMIN_CLIENTS_RELOADED", "admin_clients", pins.Names(), "fingerprints", pins.Fingerprints())
		}
		if err := f.Reload(); err != nil {
			a.log.Error("failed to reload server certificate (keeping the previous one)", "event_id", "CA_SERVER_CERT_RELOAD_ERR", "error", err.Error())
		} else {
			a.log.Info("reloaded server certificate", "event_id", "CA_SERVER_CERT_RELOADED", "fingerprint", certs.Fingerprint(f.Leaf()), "not_after", f.Leaf().NotAfter)
		}
	}
	return run, reload, nil
}

// newIdentifier は、画面の要求から利用者を決める方法を作る（Cloudflare Access の JWT、または開発用の設定）。
func newIdentifier(ctx context.Context, cfg config.Config, log *slog.Logger) (auth.Identifier, error) {
	if cfg.DevMode() {
		log.Warn("development mode: requests are not authenticated; every request acts as the development user "+
			"(CA_DEV_USER_EMAIL). Do not use this setting in production", "email", cfg.DevUserEmail, "addr", cfg.GUIAddr)
		return auth.Dev(cfg.DevUserEmail), nil
	}
	v, err := access.New(access.Options{TeamDomain: cfg.AccessTeamDomain, AUDs: cfg.AccessAUDs,
		HTTPClient: &http.Client{Timeout: 10 * time.Second}})
	if err != nil {
		return nil, err
	}
	if n, err := v.Refresh(ctx); err != nil {
		log.Warn("cannot fetch Cloudflare Access public keys; will retry on the first request", "url", v.CertsURL(), "error", err)
	} else {
		log.Info("cloudflare access", "team_domain", cfg.AccessTeamDomain, "auds", len(cfg.AccessAUDs), "keys", n)
	}
	return auth.Access(v), nil
}

// runAll は fns を並べて動かし、どれかが終われば（失敗しても）ほかも止めて、最初の誤りを返す。
func runAll(ctx context.Context, cancel context.CancelFunc, fns ...func(context.Context) error) error {
	errc := make(chan error, len(fns))
	for _, fn := range fns {
		go func() { errc <- fn(ctx) }()
	}
	first := <-errc
	cancel()
	for range len(fns) - 1 {
		if err := <-errc; first == nil {
			first = err
		}
	}
	return first
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

// dbPath は CLI の操作の DB のファイル（CA_DB_PATH。ほかの設定は要らない）。
func dbPath() string { return cmp.Or(os.Getenv("CA_DB_PATH"), "/data/radsec-ca.db") }

// openForCLI は CLI の操作の DB を開く。監査ログは日ごとのファイルにも書く（CA_AUDIT_DIR）。
func openForCLI(ctx context.Context) (*db.DB, error) {
	d, err := db.Open(ctx, dbPath())
	if err != nil {
		return nil, err
	}
	dir := cmp.Or(os.Getenv("CA_AUDIT_DIR"), filepath.Join(filepath.Dir(dbPath()), "audit"))
	if err := audit.CheckWritableDir(dir); err != nil {
		d.Close()
		return nil, err
	}
	d.SetAuditSink(audit.NewFiles(dir, 0))
	return d, nil
}

const rotateKEKUsage = `usage: radsec-ca rotate-kek -old <ファイル> -new <ファイル>

すべての CA の鍵を、古い KEK で復号して新しい KEK で暗号化し直す（1 つのトランザクション。設計概要 §6.3）。
本CA を止めてから行い、終わったら KEK のファイル（CA_KEK_FILE）を新しいものに置き換えてから起動する。
DB は CA_DB_PATH（既定 /data/radsec-ca.db）。

options:
`

func rotateKEK(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("rotate-kek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, rotateKEKUsage)
		fs.PrintDefaults()
	}
	oldPath := fs.String("old", "", "今の KEK のファイル")
	newPath := fs.String("new", "", "新しい KEK のファイル（radsec-ca gen-kek で作る）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *oldPath == "" || *newPath == "" || fs.NArg() > 0 {
		fs.Usage()
		return errors.New("-old and -new are required")
	}
	oldKEK, err := kek.Load(*oldPath)
	if err != nil {
		return err
	}
	newKEK, err := kek.Load(*newPath)
	if err != nil {
		return err
	}
	if oldKEK.ID() == newKEK.ID() {
		return errors.New("the new KEK is the same as the old one")
	}
	d, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer d.Close()
	// 新しい版のイメージで起動する前に入れ替えるときに備えて、スキーマを移行しておく。
	if _, err := d.Migrate(ctx); err != nil {
		return err
	}
	sig := &signer.Local{DB: d, KEK: oldKEK}
	n, err := sig.Rekey(ctx, newKEK)
	if err != nil {
		return err
	}
	if err := d.InsertAudit(ctx, db.AuditEntry{Operator: "cli", Source: db.SourceCLI, Action: "kek.rotate", Target: newKEK.ID(),
		Detail: map[string]any{"old_kek_id": oldKEK.ID(), "new_kek_id": newKEK.ID(), "cas": n}}); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "%d 個の CA の鍵を新しい KEK（%s）で暗号化し直しました。CA_KEK_FILE を新しいファイルに置き換えてから起動してください。\n", n, newKEK.ID())
	return nil
}

const backupUsage = `usage: radsec-ca backup -out <ファイル>

動かしたまま DB の写しを作る（SQLite の VACUUM INTO。既存のファイルは上書きしない。設計概要 §6.3）。
写しには暗号化した CA の鍵が入る。KEK と一緒に置かない。DB は CA_DB_PATH（既定 /data/radsec-ca.db）。

options:
`

func backup(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, backupUsage)
		fs.PrintDefaults()
	}
	out := fs.String("out", "", "写しのファイル")
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
	d, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Backup(ctx, *out); err != nil {
		return err
	}
	if err := d.InsertAudit(ctx, db.AuditEntry{Operator: "cli", Source: db.SourceCLI, Action: "backup", Target: filepath.Base(*out)}); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "DB の写しを作りました: %s（KEK とは別の場所に保管してください）\n", *out)
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

// replaceServerCert は管理API のサーバー証明書を作り直す（SAN は CA_TLS_HOSTS）。新しい証明書を標準出力に出す。
// 動いているサーバーは SIGHUP で読み直す。監査ログに残す。
func replaceServerCert(ctx context.Context, stdout, stderr io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if len(cfg.TLSHosts) == 0 {
		return errors.New("CA_TLS_HOSTS is required (the SAN of the API server certificate)")
	}
	d, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer d.Close()
	certPath, keyPath := filepath.Join(cfg.TLSDir, "server.pem"), filepath.Join(cfg.TLSDir, "server.key")
	certPEM, err := certs.Replace(certPath, keyPath, cfg.TLSHosts)
	if err != nil {
		return err
	}
	f, err := certs.LoadFile(certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	fp := certs.Fingerprint(f.Leaf())
	if err := d.InsertAudit(ctx, db.AuditEntry{Operator: "cli", Source: db.SourceCLI, Action: "server-cert.replace", Target: fp,
		Detail: map[string]any{"hosts": cfg.TLSHosts, "not_after": f.Leaf().NotAfter.UTC().Format(time.RFC3339)}}); err != nil {
		return err
	}
	stdout.Write(certPEM)
	fmt.Fprintf(stderr, "サーバー証明書を作り直しました（SAN: %v）。SHA-256 フィンガープリント: %s（有効期限 %s）。SIGHUP を送ると新しい証明書を使います。\n",
		cfg.TLSHosts, fp, f.Leaf().NotAfter.Local().Format(time.DateOnly))
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
