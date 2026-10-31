package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/crlfetch"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/names"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

const (
	// maxCACertBytes は受け付ける持ち込みの CA の証明書（PEM）の大きさの上限。
	maxCACertBytes = 16 << 10
	// broughtConcurrency は定期の取得の同時の数（テナント 1,000 でも 1 時間に収まる）。
	broughtConcurrency = 5
	// crlClockSkew は thisUpdate が未来でも受ける時計のずれ。
	crlClockSkew = 5 * time.Minute
	// failuresToWarn は警告を出す、続けて失敗した回数（§19.3）。
	failuresToWarn = 3
	// warnRemaining は警告を出す nextUpdate までの残り（§19.3。CRL の有効期間がこの 2 倍より短いときは、その半分）。
	warnRemaining = 3 * 24 * time.Hour
)

// oidDeltaCRLIndicator は差分の CRL の印（RFC 5280 §5.2.4）。
var oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// SecretBox は Meraki の API キーの暗号化を受け持つ（signer.Local）。
type SecretBox interface {
	SealMerakiKey(caID, key string) (enc, nonce []byte, kekID string, err error)
	OpenMerakiKey(c db.CA) (string, error)
}

// CRLSource は持ち込みの CA の CRL の取得先（§19.3）。
type CRLSource struct {
	// Source は url / meraki / upload / none。
	Source string
	// URL は url のとき、MerakiOrgID と MerakiAPIKey は meraki のとき、PEM は upload のとき。
	URL, MerakiOrgID, MerakiAPIKey string
	PEM                            []byte
}

// BroughtRequest は持ち込みの CA の登録の要求（§19.2）。
type BroughtRequest struct {
	Tenant, Name string
	// CertPEM は CA の証明書（PEM を 1 つ）。
	CertPEM []byte
	CRL     CRLSource
	// TenantOnlyConfirmed は、このテナント専用の CA であることを確かめたこと。NoCRLAccepted は CRL がないことの了承。
	TenantOnlyConfirmed, NoCRLAccepted bool
}

// checkBroughtKey は持ち込みの CA の鍵の種類を確かめる（業者の鍵はこちらで選べないので、CSR より広く受ける）。
func checkBroughtKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521() {
			return nil
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return nil
		}
	}
	return newError(CauseKeyTypeUnsupported, "certPem", "使えない鍵です（ECDSA P-256 / P-384 / P-521、RSA 2048 ビット以上だけ）")
}

// parseBroughtCert は持ち込みの CA の証明書を読み、CA として使えることを確かめる（§19.2）。
func parseBroughtCert(data []byte, now time.Time, needCRLSign bool) (*x509.Certificate, error) {
	if len(data) > maxCACertBytes {
		return nil, newError(CauseValidation, "certPem", "CA の証明書が大きすぎます（%d バイトまで）", maxCACertBytes)
	}
	block, rest := pem.Decode(bytes.TrimSpace(data))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, newError(CauseValidation, "certPem", "PEM の CA の証明書（CERTIFICATE）を 1 つだけ与えてください")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, newError(CauseValidation, "certPem", "CA の証明書が読めません: %v", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, newError(CauseValidation, "certPem", "BasicConstraints が CA の証明書ではありません")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, newError(CauseValidation, "certPem", "KeyUsage に keyCertSign がありません")
	}
	if needCRLSign && cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, newError(CauseValidation, "certPem", "KeyUsage に cRLSign がないので、この CA の CRL を検証できません")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, newError(CauseValidation, "certPem", "CA の証明書が有効期間の外です")
	}
	if err := checkBroughtKey(cert.PublicKey); err != nil {
		return nil, err
	}
	return cert, nil
}

// isSelfSigned は証明書が自己署名か。
func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// fingerprint は証明書の SHA-256（16 進小文字）。
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// checkCRLSource は取得先の項目の形を確かめる。
func checkCRLSource(src CRLSource, noCRLAccepted bool) error {
	switch src.Source {
	case db.CRLSourceURL:
		if err := crlfetch.CheckURL(src.URL); err != nil {
			return newError(CauseValidation, "crl.url", "CRL の URL が正しくありません: %v", err)
		}
	case db.CRLSourceMeraki:
		if err := crlfetch.CheckOrgID(src.MerakiOrgID); err != nil {
			return newError(CauseValidation, "crl.merakiOrgId", "Meraki の組織の ID が正しくありません: %v", err)
		}
	case db.CRLSourceUpload:
		if len(src.PEM) == 0 {
			return newError(CauseCRLRequired, "crl.pem", "CRL を与えてください")
		}
	case db.CRLSourceNone:
		if !noCRLAccepted {
			return newError(CauseNoCRLNotAccepted, "noCrlAccepted", "CRL がなく、業者の AP の失効が効かないことの了承が要ります")
		}
	default:
		return newError(CauseValidation, "crl.source", "CRL の取得先は url・meraki・upload・none のどれかにしてください")
	}
	return nil
}

// checkCRL は CRL を置いてよいか確かめ、読み取った CRL を返す（§19.3）。latest は今の CRL（なければ nil）。
func checkCRL(der []byte, cert *x509.Certificate, latest *db.CRL, now time.Time) (*x509.RevocationList, error) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("the CRL cannot be parsed: %w", err)
	}
	if !bytes.Equal(rl.RawIssuer, cert.RawSubject) {
		return nil, errors.New("the issuer of the CRL is not this CA")
	}
	if err := rl.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("the signature of the CRL cannot be verified with this CA: %w", err)
	}
	for _, e := range rl.Extensions {
		if e.Id.Equal(oidDeltaCRLIndicator) {
			return nil, errors.New("delta CRLs are not accepted")
		}
	}
	if rl.ThisUpdate.After(now.Add(crlClockSkew)) {
		return nil, errors.New("thisUpdate of the CRL is in the future")
	}
	if rl.NextUpdate.IsZero() {
		return nil, errors.New("the CRL has no nextUpdate")
	}
	if !rl.NextUpdate.After(now) {
		return nil, errors.New("nextUpdate of the CRL has passed")
	}
	if latest != nil {
		// 古い CRL を置かれると、失効が取り消されたように見えるので、番号（なければ時刻）の後退を断る。
		old, oldOK := new(big.Int).SetString(latest.ExtNumber, 10)
		switch {
		case oldOK && rl.Number != nil:
			if rl.Number.Cmp(old) < 0 {
				return nil, fmt.Errorf("cRLNumber went backwards (%s, now %s)", rl.Number, old)
			}
		case rl.ThisUpdate.Before(latest.ThisUpdate):
			return nil, errors.New("thisUpdate of the CRL is older than the current one")
		}
	}
	return rl, nil
}

// crlRow は読み取った CRL を DB の行にする。
func crlRow(der []byte, rl *x509.RevocationList, now time.Time) db.CRL {
	ext := ""
	if rl.Number != nil {
		ext = rl.Number.String()
	}
	return db.CRL{ExtNumber: ext, ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate, DER: der, CreatedAt: now}
}

// fetched は取得の結果。
type fetched struct {
	der            []byte
	etag, modified string
	notModified    bool
}

// fetch は取得先から CRL を取る。
func (s *Service) fetch(ctx context.Context, src CRLSource, cert *x509.Certificate, etag, modified string) (fetched, error) {
	switch src.Source {
	case db.CRLSourceURL:
		r, err := s.Fetcher.FetchURL(ctx, src.URL, etag, modified)
		if err != nil {
			return fetched{}, err
		}
		return fetched{der: r.DER, etag: r.ETag, modified: r.LastModified, notModified: r.NotModified}, nil
	case db.CRLSourceMeraki:
		// 応答には組織のすべての CA の CRL が入る。発行者と署名で、この CA のものを選ぶ（§19.3）。
		match := func(der []byte) bool {
			rl, err := x509.ParseRevocationList(der)
			return err == nil && bytes.Equal(rl.RawIssuer, cert.RawSubject) && rl.CheckSignatureFrom(cert) == nil
		}
		ders, err := s.Fetcher.FetchMeraki(ctx, src.MerakiOrgID, src.MerakiAPIKey, match)
		if err != nil {
			return fetched{}, err
		}
		best := ders[0]
		var bestAt time.Time
		for _, der := range ders {
			if rl, err := x509.ParseRevocationList(der); err == nil && rl.ThisUpdate.After(bestAt) {
				best, bestAt = der, rl.ThisUpdate
			}
		}
		return fetched{der: best}, nil
	case db.CRLSourceUpload:
		der, err := crlfetch.ParseBytes(src.PEM)
		if err != nil {
			return fetched{}, err
		}
		return fetched{der: der}, nil
	}
	return fetched{}, fmt.Errorf("unknown CRL source %q", src.Source)
}

// RegisterBrought は持ち込みの CA を登録する（§19.2）。url・meraki・upload では、その場で CRL が取れて確かめられたときだけ
// 成功し、失敗なら何も残さない（CA の行は消さない作りなので、誤った取得先を残さないため）。
func (s *Service) RegisterBrought(ctx context.Context, a Actor, req BroughtRequest) (db.CA, error) {
	if err := names.CheckTenant(req.Tenant); err != nil {
		return db.CA{}, newError(CauseValidation, "tenant", "テナントの名前は、%v", err)
	}
	if !names.ValidSlug(req.Name) {
		return db.CA{}, newError(CauseValidation, "name", "持ち込みの CA の名前は、%v", names.ErrSlug)
	}
	if !req.TenantOnlyConfirmed {
		return db.CA{}, newError(CauseTenantOnlyNotConfirmed, "tenantOnlyConfirmed", "このテナント専用の CA であることの確認が要ります")
	}
	if err := checkCRLSource(req.CRL, req.NoCRLAccepted); err != nil {
		return db.CA{}, err
	}
	now := s.Now()
	cert, err := parseBroughtCert(req.CertPEM, now, req.CRL.Source != db.CRLSourceNone)
	if err != nil {
		return db.CA{}, err
	}
	if req.CRL.Source == db.CRLSourceMeraki && req.CRL.MerakiAPIKey == "" {
		return db.CA{}, newError(CauseValidation, "crl.merakiApiKey", "Meraki の API キーを与えてください")
	}
	id := signer.BroughtCAID(req.Tenant, req.Name)
	fp := fingerprint(cert.Raw)
	// 外へ取りに行く前に、分かる誤りを返す。
	if err := s.checkBroughtFree(ctx, id, fp); err != nil {
		return db.CA{}, err
	}
	rec := db.CA{ID: id, Kind: db.KindTenantBrought, Tenant: req.Tenant, CertDER: cert.Raw, Status: db.StatusActive,
		NotAfter: cert.NotAfter, CreatedAt: now, SelfSigned: isSelfSigned(cert), Fingerprint: fp, CRLSource: req.CRL.Source,
		CRLURL: req.CRL.URL, MerakiOrgID: req.CRL.MerakiOrgID, TenantOnlyBy: actorName(a), TenantOnlyAt: now}
	if req.CRL.Source == db.CRLSourceNone {
		rec.NoCRLBy, rec.NoCRLAt = actorName(a), now
	}
	if req.CRL.Source == db.CRLSourceMeraki {
		if rec.MerakiKeyEnc, rec.MerakiKeyNonce, rec.KEKID, err = s.Secrets.SealMerakiKey(id, req.CRL.MerakiAPIKey); err != nil {
			return db.CA{}, err
		}
	}
	var crl *db.CRL
	if req.CRL.Source != db.CRLSourceNone {
		// 外への通信の間は、発行や失効を止めないようにロックを持たない。
		got, err := s.fetch(ctx, req.CRL, cert, "", "")
		if err != nil {
			return db.CA{}, newError(CauseCRLInvalid, "crl", "CRL を取れません: %v", err)
		}
		rl, err := checkCRL(got.der, cert, nil, now)
		if err != nil {
			return db.CA{}, newError(CauseCRLInvalid, "crl", "CRL を置けません: %v", err)
		}
		row := crlRow(got.der, rl, now)
		crl = &row
		rec.CRLETag, rec.CRLModified, rec.CRLCheckedAt, rec.CRLOKAt = got.etag, got.modified, now, now
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkBroughtFree(ctx, id, fp); err != nil {
		return db.CA{}, err
	}
	if err := s.DB.InsertBrought(ctx, rec, crl); err != nil {
		if errors.Is(err, db.ErrConflict) {
			return db.CA{}, newError(CauseCAExists, "name", "CA %s はすでにあります", id)
		}
		return db.CA{}, err
	}
	s.audit(ctx, a, "ca.register", id, "ok", map[string]any{"tenant": req.Tenant, "name": req.Name, "fingerprint": fp, "self_signed": rec.SelfSigned,
		"subject": cert.Subject.String(), "crl_source": req.CRL.Source, "crl_url": req.CRL.URL, "meraki_org_id": req.CRL.MerakiOrgID,
		"tenant_only_confirmed": true, "no_crl_accepted": req.CRL.Source == db.CRLSourceNone})
	return s.DB.CA(ctx, id)
}

// checkBroughtFree は ID と CA が使われていないことを確かめる。
func (s *Service) checkBroughtFree(ctx context.Context, id, fp string) error {
	if _, err := s.DB.CA(ctx, id); err == nil {
		return newError(CauseCAExists, "name", "CA %s はすでにあります（止めた CA の名前も使えません）", id)
	} else if !errors.Is(err, db.ErrNotFound) {
		return err
	}
	if other, err := s.DB.ActiveBroughtByFingerprint(ctx, fp); err == nil {
		return newError(CauseFingerprintInUse, "certPem", "同じ CA が %s として登録されています", other.ID)
	} else if !errors.Is(err, db.ErrNotFound) {
		return err
	}
	return nil
}

// actorName は操作者の名前（確認と了承の記録に残す）。
func actorName(a Actor) string {
	if a.Operator != "" {
		return a.Operator
	}
	return a.MgmtClient
}

// activeBrought は有効な持ち込みの CA を返す（それ以外は呼び出し側の誤り）。
func (s *Service) activeBrought(ctx context.Context, caID string) (db.CA, *x509.Certificate, error) {
	c, err := s.DB.CA(ctx, caID)
	if errors.Is(err, db.ErrNotFound) {
		return db.CA{}, nil, newError(CauseCANotFound, "caId", "CA %s はありません", caID)
	}
	if err != nil {
		return db.CA{}, nil, err
	}
	if c.Kind != db.KindTenantBrought {
		return db.CA{}, nil, newError(CauseValidation, "caId", "CA %s は持ち込みの CA ではありません", caID)
	}
	if c.Status != db.StatusActive {
		return db.CA{}, nil, newError(CauseCADisabled, "caId", "CA %s は停止しています", caID)
	}
	cert, err := x509.ParseCertificate(c.CertDER)
	if err != nil {
		return db.CA{}, nil, fmt.Errorf("CA %s: certificate: %w", caID, err)
	}
	return c, cert, nil
}

// sourceOf は CA の記録から取得先を作る（API キーを復号する）。
func (s *Service) sourceOf(c db.CA) (CRLSource, error) {
	src := CRLSource{Source: c.CRLSource, URL: c.CRLURL, MerakiOrgID: c.MerakiOrgID}
	if c.CRLSource == db.CRLSourceMeraki {
		key, err := s.Secrets.OpenMerakiKey(c)
		if err != nil {
			return CRLSource{}, err
		}
		src.MerakiAPIKey = key
	}
	return src, nil
}

// failCRL は取得の失敗を記録する。誤りを返す。
func (s *Service) failCRL(ctx context.Context, c db.CA, cause error) error {
	st := db.CRLState{ETag: c.CRLETag, Modified: c.CRLModified, CheckedAt: s.Now(), OKAt: c.CRLOKAt, Failures: c.CRLFailures + 1, LastError: cause.Error()}
	if err := s.DB.SetCRLState(context.WithoutCancel(ctx), c.ID, st); err != nil {
		s.Log.Error("cannot record crl state", "ca", c.ID, "error", err)
	}
	s.Log.Warn("cannot update the brought CRL", "event_id", "CA_BROUGHT_CRL_FAILED", "ca", c.ID, "source", c.CRLSource, "failures", st.Failures, "error", cause.Error())
	return newError(CauseCRLInvalid, "crl", "CRL を置けません: %v", cause)
}

// RefreshBrought は持ち込みの CA の CRL をすぐ取りに行く（url か meraki。§19.5）。置けなければ今の CRL を残す。
func (s *Service) RefreshBrought(ctx context.Context, caID string) error {
	c, cert, err := s.activeBrought(ctx, caID)
	if err != nil {
		return err
	}
	if c.CRLSource != db.CRLSourceURL && c.CRLSource != db.CRLSourceMeraki {
		return newError(CauseValidation, "caId", "CA %s の CRL の取得先（%s）は取りに行けません", caID, c.CRLSource)
	}
	src, err := s.sourceOf(c)
	if err != nil {
		return s.failCRL(ctx, c, err)
	}
	got, err := s.fetch(ctx, src, cert, c.CRLETag, c.CRLModified)
	if err != nil {
		return s.failCRL(ctx, c, err)
	}
	return s.acceptCRL(ctx, c, cert, got)
}

// acceptCRL は取ってきた CRL を確かめて置く。中身が今と同じなら置かない。
func (s *Service) acceptCRL(ctx context.Context, c db.CA, cert *x509.Certificate, got fetched) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	st := db.CRLState{ETag: got.etag, Modified: got.modified, CheckedAt: now, OKAt: now}
	latest, err := s.DB.LatestCRL(ctx, c.ID)
	var cur *db.CRL
	switch {
	case err == nil:
		cur = &latest
	case !errors.Is(err, db.ErrNotFound):
		return err
	}
	if got.notModified || (cur != nil && bytes.Equal(cur.DER, got.der)) {
		return s.DB.SetCRLState(ctx, c.ID, st)
	}
	rl, err := checkCRL(got.der, cert, cur, now)
	if err != nil {
		return s.failCRL(ctx, c, err)
	}
	if err := s.DB.PutBroughtCRL(ctx, c.ID, crlRow(got.der, rl, now), st); err != nil {
		return err
	}
	s.Log.Info("brought CRL updated", "event_id", "CA_BROUGHT_CRL_UPDATED", "ca", c.ID, "source", c.CRLSource, "revoked", len(rl.RevokedCertificateEntries),
		"next_update", rl.NextUpdate.UTC().Format(time.RFC3339))
	return nil
}

// UploadCRL は取得先が upload の CA に CRL を置く（§19.3）。data は PEM か DER。
func (s *Service) UploadCRL(ctx context.Context, a Actor, caID string, data []byte) error {
	c, cert, err := s.activeBrought(ctx, caID)
	if err != nil {
		return err
	}
	if c.CRLSource != db.CRLSourceUpload {
		return newError(CauseValidation, "caId", "CA %s の CRL の取得先は %s です（アップロードは受けません）", caID, c.CRLSource)
	}
	der, err := crlfetch.ParseBytes(data)
	if err != nil {
		return newError(CauseCRLInvalid, "crl", "CRL を読めません: %v", err)
	}
	if err := s.acceptCRL(ctx, c, cert, fetched{der: der}); err != nil {
		return err
	}
	s.audit(ctx, a, "ca.crl.upload", caID, "ok", map[string]any{"sha256": fingerprint(der)})
	return nil
}

// ChangeCRLSource は CRL の取得先を変える（§19.5）。新しい取得先から取れると確かめてから替える。
func (s *Service) ChangeCRLSource(ctx context.Context, a Actor, caID string, src CRLSource, noCRLAccepted bool) (db.CA, error) {
	c, cert, err := s.activeBrought(ctx, caID)
	if err != nil {
		return db.CA{}, err
	}
	if err := checkCRLSource(src, noCRLAccepted); err != nil {
		return db.CA{}, err
	}
	if src.Source != db.CRLSourceNone && cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return db.CA{}, newError(CauseValidation, "crl.source", "CA の KeyUsage に cRLSign がないので、この CA の CRL を検証できません")
	}
	now := s.Now()
	ch := db.CRLSourceChange{Source: src.Source, URL: src.URL, MerakiOrgID: src.MerakiOrgID}
	if src.Source == db.CRLSourceMeraki {
		switch {
		case src.MerakiAPIKey != "":
			if ch.MerakiKeyEnc, ch.MerakiKeyNonce, _, err = s.Secrets.SealMerakiKey(caID, src.MerakiAPIKey); err != nil {
				return db.CA{}, err
			}
		case c.CRLSource == db.CRLSourceMeraki:
			// 組織の ID だけを変えるときは、今のキーを使う。
			ch.MerakiKeyEnc, ch.MerakiKeyNonce = c.MerakiKeyEnc, c.MerakiKeyNonce
			if src.MerakiAPIKey, err = s.Secrets.OpenMerakiKey(c); err != nil {
				return db.CA{}, err
			}
		default:
			return db.CA{}, newError(CauseValidation, "crl.merakiApiKey", "Meraki の API キーを与えてください")
		}
	}
	if src.Source == db.CRLSourceNone {
		ch.NoCRLBy, ch.NoCRLAt = actorName(a), now
	}
	var row *db.CRL
	if src.Source != db.CRLSourceNone {
		got, err := s.fetch(ctx, src, cert, "", "")
		if err != nil {
			return db.CA{}, newError(CauseCRLInvalid, "crl", "CRL を取れません: %v", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		latest, err := s.DB.LatestCRL(ctx, caID)
		var cur *db.CRL
		switch {
		case err == nil:
			cur = &latest
		case !errors.Is(err, db.ErrNotFound):
			return db.CA{}, err
		}
		rl, err := checkCRL(got.der, cert, cur, now)
		if err != nil {
			return db.CA{}, newError(CauseCRLInvalid, "crl", "CRL を置けません: %v", err)
		}
		if cur == nil || !bytes.Equal(cur.DER, got.der) {
			r := crlRow(got.der, rl, now)
			row = &r
		}
		ch.State = db.CRLState{ETag: got.etag, Modified: got.modified, CheckedAt: now, OKAt: now}
	} else {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if err := s.DB.ChangeCRLSource(ctx, caID, ch, row); err != nil {
		return db.CA{}, err
	}
	s.audit(ctx, a, "ca.crl_source.change", caID, "ok", map[string]any{"from": c.CRLSource, "to": src.Source, "crl_url": src.URL,
		"meraki_org_id": src.MerakiOrgID, "no_crl_accepted": src.Source == db.CRLSourceNone})
	return s.DB.CA(ctx, caID)
}

// CRLWarning は持ち込みの CA の CRL の警告の文を返す（なければ空。§19.3）。停止した CA には出さない。
func CRLWarning(c db.CA, latest *db.CRL, now time.Time) string {
	if c.Kind != db.KindTenantBrought || c.Status != db.StatusActive || c.CRLSource == db.CRLSourceNone {
		return ""
	}
	var out []string
	if c.CRLFailures >= failuresToWarn {
		out = append(out, fmt.Sprintf("%d 回続けて更新に失敗しています", c.CRLFailures))
	}
	if latest != nil {
		threshold := warnRemaining
		if half := latest.NextUpdate.Sub(latest.ThisUpdate) / 2; half < threshold {
			threshold = half
		}
		if left := latest.NextUpdate.Sub(now); left <= 0 {
			out = append(out, "nextUpdate を過ぎました")
		} else if left < threshold {
			out = append(out, "nextUpdate が近づいています")
		}
	}
	return strings.Join(out, "。")
}

// RefreshBroughtCRLs は取りに行く時期の持ち込みの CA の CRL を、同時に broughtConcurrency 件まで取りに行く（定期の処理）。
// 置けなかった CA の数を返す。
func (s *Service) RefreshBroughtCRLs(ctx context.Context) int {
	due, err := s.DB.BroughtDue(ctx, s.Now().Add(-s.BroughtCRLRefresh))
	if err != nil {
		s.Log.Error("refresh brought crls", "event_id", "CA_BROUGHT_CRL_FAILED", "error", err)
		return 1
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	sem := make(chan struct{}, broughtConcurrency)
	for _, c := range due {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			if err := s.RefreshBrought(ctx, c.ID); err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return failed
}
