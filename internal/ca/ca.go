// Package ca は本CA の中心の処理を受け持つ: CA の作成と停止、プロファイルによる発行（設計概要 §5）、失効と CRL（§7）。
// 画面と管理API はここを呼ぶ。
package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/crlfetch"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/names"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// caValidity は CA の証明書の有効期間（10 年。§5.1）。
const caValidity = 10 * 365 * 24 * time.Hour

// Options は Service の設定。
type Options struct {
	Log    *slog.Logger
	DB     *db.DB
	Signer signer.Signer
	// Org は CA の Subject の O と CN に入れる組織の名前。URNPrefix と DNSDomain は名前の規則の値。
	Org, URNPrefix, DNSDomain string
	// APCertDays・GroupCertDays・ServerCertDays は有効期限（日）。
	APCertDays, GroupCertDays, ServerCertDays int
	// CRLValidity は CRL の nextUpdate までの長さ、CRLRefresh は作り直しの間隔。
	CRLValidity, CRLRefresh time.Duration
	// Fetcher は持ち込みの CA の CRL を取ってくる。BroughtCRLRefresh は取りに行く間隔。Secrets は Meraki の API キーを暗号化する。
	Fetcher           *crlfetch.Fetcher
	BroughtCRLRefresh time.Duration
	Secrets           SecretBox
	// Now は現在時刻（テストで差し替える）。
	Now func() time.Time
}

// Service は本CA の中心の処理。
type Service struct {
	Options
	// mu は CA の作成・停止・発行・失効・CRL の作成を 1 つずつにする（CRL の番号を飛ばさない・重ねないため）。
	mu sync.Mutex
	// crlErrors は CA ごとの CRL の作り直しの失敗（errMu で守る）。
	errMu     sync.Mutex
	crlErrors map[string]string
}

// New は Service を作る。
func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{Options: o}
}

// Actor は操作した人（監査ログに残す）。
type Actor struct {
	// Operator は画面の利用者のメールアドレス、または X-Operator-Id。MgmtClient は管理API の管理クライアントの識別名。
	Operator, MgmtClient string
	// Source は api / gui / cli / system。
	Source  string
	TraceID string
}

// System は定期の処理と起動のときの処理の操作者。
var System = Actor{Operator: "system", Source: db.SourceSystem}

// audit は監査ログを書き、標準出力にも出す（§13）。書けなくても操作は失敗にしない。
func (s *Service) audit(ctx context.Context, a Actor, action, target, result string, detail map[string]any) {
	err := s.DB.InsertAudit(context.WithoutCancel(ctx), db.AuditEntry{Operator: a.Operator, MgmtClient: a.MgmtClient, Source: a.Source,
		Action: action, Target: target, Result: result, Detail: detail, TraceID: a.TraceID})
	if err != nil {
		s.Log.Error("cannot write audit log", "event_id", "CA_AUDIT_WRITE_ERR", "action", action, "target", target, "error", err)
	}
	s.Log.Info("audit", "event_id", "CA_AUDIT", "operator", a.Operator, "mgmt_client", a.MgmtClient, "source", a.Source,
		"action", action, "target", target, "result", result, "trace_id", a.TraceID)
}

func (s *Service) caSubject(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{s.Org}}
}

// Init は、サーバーCA がなければ作る（初めて起動したとき。§12）。作ったら true を返す。
func (s *Service) Init(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.DB.CA(ctx, signer.ServerCAID); err == nil {
		return false, nil
	} else if !errors.Is(err, db.ErrNotFound) {
		return false, err
	}
	cert, err := s.Signer.CreateCA(ctx, signer.ServerCAID, s.caSubject(s.Org+" RadSec server CA"), caValidity)
	if err != nil {
		return false, fmt.Errorf("create server CA: %w", err)
	}
	s.audit(ctx, System, "ca.create", signer.ServerCAID, "ok", map[string]any{"subject": cert.Subject.String(), "serial": serialHex(cert)})
	if err := s.publishLocked(ctx, signer.ServerCAID); err != nil {
		return true, err
	}
	return true, nil
}

// CreateTenantCA はテナントのクライアントCA（tenant.<slug>）を作る。あれば CA_EXISTS。
func (s *Service) CreateTenantCA(ctx context.Context, a Actor, tenant string) (db.CA, error) {
	if err := names.CheckTenant(tenant); err != nil {
		return db.CA{}, newError(CauseValidation, "tenant", "テナントの名前は、%v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := signer.TenantCAID(tenant)
	cert, err := s.Signer.CreateCA(ctx, id, s.caSubject(tenant+" client CA"), caValidity)
	if errors.Is(err, db.ErrConflict) {
		return db.CA{}, newError(CauseCAExists, "tenant", "テナント %s のクライアントCA はすでにあります", tenant)
	}
	if err != nil {
		return db.CA{}, err
	}
	s.audit(ctx, a, "ca.create", id, "ok", map[string]any{"subject": cert.Subject.String(), "serial": serialHex(cert)})
	// 作った CA の最初の CRL を作る（エッジがすぐに取りに来られるように）。
	if err := s.publishLocked(ctx, id); err != nil {
		return db.CA{}, err
	}
	return s.DB.CA(ctx, id)
}

// IssueRequest は発行の要求。
type IssueRequest struct {
	Profile string
	Material
	// CSR は PEM の CSR（公開鍵だけを使う）。
	CSR []byte
}

// Issued は発行の結果。
type Issued struct {
	Cert db.Cert
	// CertPEM は証明書、CAPEM は署名した CA の証明書（どちらも PEM）。
	CertPEM, CAPEM []byte
}

// Issue はプロファイルと名前の材料から証明書の中身を決め、CSR の公開鍵に署名して記録する（§5）。
func (s *Service) Issue(ctx context.Context, a Actor, req IssueRequest) (Issued, error) {
	p, err := s.planFor(req.Profile, req.Material)
	if err != nil {
		return Issued{}, err
	}
	pub, err := ParseCSR(req.CSR)
	if err != nil {
		return Issued{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.DB.CA(ctx, p.caID)
	if errors.Is(err, db.ErrNotFound) {
		return Issued{}, newError(CauseCANotFound, "tenant", "CA %s がありません（先にテナントのクライアントCA を作ってください）", p.caID)
	}
	if err != nil {
		return Issued{}, err
	}
	if c.Status != db.StatusActive {
		return Issued{}, newError(CauseCADisabled, "tenant", "CA %s は停止しています（発行しません）", p.caID)
	}
	now := s.Now()
	var cert *x509.Certificate
	// シリアル番号は DB で全体の一意を確かめ、重なったら作り直す（§5.4）。
	for range 5 {
		tmpl, err := p.template(pub, c.NotAfter, now)
		if err != nil {
			return Issued{}, err
		}
		if used, err := s.DB.SerialExists(ctx, tmpl.SerialNumber.Text(16)); err != nil {
			return Issued{}, err
		} else if used {
			continue
		}
		if cert, err = s.Signer.SignCertificate(ctx, p.caID, tmpl, pub); err != nil {
			return Issued{}, err
		}
		break
	}
	if cert == nil {
		return Issued{}, errors.New("cannot allocate a unique serial number")
	}
	rec := db.Cert{Serial: serialHex(cert), CAID: p.caID, Profile: req.Profile, Tenant: p.tenant, AP: req.AP, Edge: req.Edge, Group: req.Group,
		CN: p.cn, SANDNS: p.dns, SANURI: p.uri, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, CertDER: cert.Raw,
		PubKeySHA256: PubKeySHA256(pub), IssuedBy: a.Operator, TraceID: a.TraceID, CreatedAt: now}
	if err := s.DB.InsertCert(ctx, rec); err != nil {
		return Issued{}, err
	}
	s.audit(ctx, a, "cert.issue", rec.Serial, "ok", map[string]any{"profile": req.Profile, "tenant": req.Tenant, "ap": req.AP,
		"edge": req.Edge, "group": req.Group, "serial": rec.Serial, "pubkey_sha256": rec.PubKeySHA256, "not_after": rec.NotAfter.UTC().Format(time.RFC3339)})
	s.Log.Info("certificate issued", "event_id", "CA_CERT_ISSUED", "serial", rec.Serial, "profile", req.Profile, "tenant", req.Tenant,
		"ap", req.AP, "edge", req.Edge, "group", req.Group, "trace_id", a.TraceID)
	return Issued{Cert: rec, CertPEM: CertPEM(cert.Raw), CAPEM: CertPEM(c.CertDER)}, nil
}

// serialHex はシリアル番号の 16 進（小文字）。
func serialHex(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

// CertPEM は証明書の DER を PEM にする。
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Audit は ca の外の操作（利用者の変更、KEK の入れ替え、バックアップ）の監査ログを書く。
func (s *Service) Audit(ctx context.Context, a Actor, action, target string, detail map[string]any) {
	s.audit(ctx, a, action, target, "ok", detail)
}
