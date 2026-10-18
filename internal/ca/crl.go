package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// 失効の理由（§7.1）。RFC 5280 の CRLReason の値。
var revokeReasons = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"superseded":           4,
	"cessationOfOperation": 5,
}

// ValidReason は失効の理由として受け付ける値か。
func ValidReason(r string) bool {
	_, ok := revokeReasons[r]
	return ok
}

// publishLocked は CA caID の CRL を作り直して記録する（§7.2）。番号を 1 つ進め、失効させた証明書のうち期限の切れていない
// ものを載せ、nextUpdate は thisUpdate の CRLValidity 後にする。s.mu を持って呼ぶ。
func (s *Service) publishLocked(ctx context.Context, caID string) error {
	number, err := s.DB.NextCRLNumber(ctx, caID)
	if err != nil {
		return err
	}
	now := s.Now()
	revoked, err := s.DB.RevokedForCRL(ctx, caID, now)
	if err != nil {
		return err
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now,
		NextUpdate: now.Add(s.CRLValidity),
	}
	for _, r := range revoked {
		e := x509.RevocationListEntry{SerialNumber: r.Serial, RevocationTime: r.RevokedAt}
		if code := revokeReasons[r.Reason]; code != 0 {
			e.ReasonCode = code
		}
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, e)
	}
	der, err := s.Signer.CreateCRL(ctx, caID, tmpl)
	if err != nil {
		s.Log.Error("cannot create crl", "event_id", "CA_CRL_FAILED", "ca", caID, "error", err)
		return fmt.Errorf("create crl for %s: %w", caID, err)
	}
	if err := s.DB.InsertCRL(ctx, db.CRL{CAID: caID, Number: number, ThisUpdate: now, NextUpdate: tmpl.NextUpdate, DER: der, CreatedAt: now}); err != nil {
		return err
	}
	s.Log.Info("crl published", "event_id", "CA_CRL_PUBLISHED", "ca", caID, "number", number, "revoked", len(revoked),
		"next_update", tmpl.NextUpdate.UTC().Format(time.RFC3339))
	return nil
}

// Revoke は証明書を失効させ、その CA の CRL をすぐ作り直す（§7.1）。失効していれば何もしない（成功として扱う）。
// 失効させたら true を返す。
func (s *Service) Revoke(ctx context.Context, a Actor, serial, reason string) (bool, error) {
	if !ValidReason(reason) {
		return false, newError(CauseValidation, "reason", "理由は unspecified・keyCompromise・superseded・cessationOfOperation のどれかにしてください")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.DB.Cert(ctx, serial)
	if errors.Is(err, db.ErrNotFound) {
		return false, newError(CauseCertNotFound, "serial", "シリアル番号 %s の証明書はありません", serial)
	}
	if err != nil {
		return false, err
	}
	changed, err := s.DB.RevokeCert(ctx, serial, reason, s.Now())
	if err != nil || !changed {
		return false, err
	}
	s.audit(ctx, a, "cert.revoke", serial, "ok", map[string]any{"serial": serial, "reason": reason, "profile": c.Profile,
		"tenant": c.Tenant, "ap": c.AP, "edge": c.Edge, "ca": c.CAID})
	s.Log.Info("certificate revoked", "event_id", "CA_CERT_REVOKED", "serial", serial, "reason", reason, "ca", c.CAID, "trace_id", a.TraceID)
	if err := s.publishLocked(ctx, c.CAID); err != nil {
		s.setCRLError(c.CAID, err)
		return true, err
	}
	s.setCRLError(c.CAID, nil)
	return true, nil
}

// DisableCA はテナントをやめる（§7.4）。テナントのクライアントCA を停止し、有効な証明書をすべて cessationOfOperation で
// 失効させて、CRL を作り直す（停止した CA の CRL も作り続ける）。停止していれば何もしない。
func (s *Service) DisableCA(ctx context.Context, a Actor, caID string) error {
	if caID == signer.ServerCAID {
		return newError(CauseValidation, "caId", "サーバーCA は停止できません")
	}
	if _, _, err := signer.ParseCAID(caID); err != nil {
		return newError(CauseCANotFound, "caId", "CA %s はありません", caID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.DB.CA(ctx, caID); errors.Is(err, db.ErrNotFound) {
		return newError(CauseCANotFound, "caId", "CA %s はありません", caID)
	} else if err != nil {
		return err
	}
	changed, err := s.DB.DisableCA(ctx, caID)
	if err != nil || !changed {
		return err
	}
	n, err := s.DB.RevokeAllValid(ctx, caID, "cessationOfOperation", s.Now())
	if err != nil {
		return err
	}
	s.audit(ctx, a, "ca.disable", caID, "ok", map[string]any{"revoked": n})
	if err := s.publishLocked(ctx, caID); err != nil {
		s.setCRLError(caID, err)
		return err
	}
	s.setCRLError(caID, nil)
	return nil
}

// minRemaining は、起動したときなどに作り直す nextUpdate までの残り（§7.2）。
const minRemaining = 24 * time.Hour

// RefreshCRLs は、作り直しの時期になった CA の CRL を作り直す（定期の処理。§7.2）。前の CRL から CRLRefresh が経ったもの、
// nextUpdate までが 1 日を切ったもの、CRL のないものを作り直す。作り直せなかった CA の数を返す。
func (s *Service) RefreshCRLs(ctx context.Context) int {
	cas, err := s.DB.CAs(ctx)
	if err != nil {
		s.Log.Error("refresh crls", "event_id", "CA_CRL_FAILED", "error", err)
		return 1
	}
	failed := 0
	for _, c := range cas {
		latest, err := s.DB.LatestCRL(ctx, c.ID)
		now := s.Now()
		due := errors.Is(err, db.ErrNotFound) || (err == nil && (now.Sub(latest.ThisUpdate) >= s.CRLRefresh || latest.NextUpdate.Sub(now) < minRemaining))
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			s.setCRLError(c.ID, err)
			failed++
			continue
		}
		if !due {
			continue
		}
		s.mu.Lock()
		err = s.publishLocked(ctx, c.ID)
		s.mu.Unlock()
		s.setCRLError(c.ID, err)
		if err != nil {
			failed++
		}
	}
	return failed
}

// setCRLError は CA の CRL の作り直しの失敗を覚える（nil なら消す。/status と画面に出す）。
func (s *Service) setCRLError(caID string, err error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.crlErrors == nil {
		s.crlErrors = map[string]string{}
	}
	if err == nil {
		delete(s.crlErrors, caID)
		return
	}
	s.crlErrors[caID] = err.Error()
}

// CRLErrors は CA ごとの CRL の作り直しの失敗を返す。
func (s *Service) CRLErrors() map[string]string {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return maps.Clone(s.crlErrors)
}

// Run は CRL の作り直しの定期の処理を、ctx が終わるまで 1 分ごとに動かす（起動したときにも 1 回行う）。
func (s *Service) Run(ctx context.Context) {
	for {
		s.RefreshCRLs(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}
