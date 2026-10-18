package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
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
