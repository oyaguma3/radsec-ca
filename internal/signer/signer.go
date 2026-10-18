// Package signer は CA の鍵による署名を受け持つ（設計概要 §6.4）。
//
// 今の実装（Local）は、DB に暗号化して入れた CA の鍵を、署名のたびに KEK で復号して使い、メモリーに持ち続けない（§6.1）。
// 後で OpenBao の PKI や HSM に差し替えられるよう、呼び出し側は Signer のインターフェースだけを使う。
package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/names"
)

// Signer は CA の鍵による署名を受け持つ。
type Signer interface {
	// CreateCA は CA の鍵と自己署名の証明書を作って記録し、証明書を返す。id は server か tenant.<slug>。
	CreateCA(ctx context.Context, id string, subject pkix.Name, validity time.Duration) (*x509.Certificate, error)
	// SignCertificate は CA caID の鍵で tmpl の証明書に署名する（公開鍵は pub）。
	SignCertificate(ctx context.Context, caID string, tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error)
	// CreateCRL は CA caID の鍵で CRL に署名し、DER を返す。
	CreateCRL(ctx context.Context, caID string, tmpl *x509.RevocationList) ([]byte, error)
}

// ServerCAID はサーバーCA の ID。TenantCAID はテナントのクライアントCA の ID（§5.1）。
const ServerCAID = "server"

// TenantCAID はテナント slug のクライアントCA の ID。
func TenantCAID(slug string) string { return "tenant." + slug }

// ParseCAID は CA の ID を読み、種類とテナントを返す。
func ParseCAID(id string) (kind, tenant string, err error) {
	if id == ServerCAID {
		return db.KindServer, "", nil
	}
	if slug, ok := strings.CutPrefix(id, "tenant."); ok && names.ValidSlug(slug) {
		return db.KindTenantClient, slug, nil
	}
	return "", "", fmt.Errorf("invalid CA id %q", id)
}

// Local は DB の暗号化した鍵で署名する Signer。
type Local struct {
	DB  *db.DB
	KEK *kek.KEK
	Now func() time.Time
}

var _ Signer = (*Local)(nil)

func (l *Local) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// NewSerial は 128 ビットの乱数のシリアル番号（正の値）を作る（§5.4）。
func NewSerial() (*big.Int, error) {
	for {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// CreateCA は ECDSA P-256 の鍵と自己署名の CA の証明書を作り、鍵を KEK で暗号化して記録する（§5.1、§6.1）。
func (l *Local) CreateCA(ctx context.Context, id string, subject pkix.Name, validity time.Duration) (*x509.Certificate, error) {
	kind, tenant, err := ParseCAID(id)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := l.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// 下に CA を作れない（pathlen:0。§5.1）。Subject Key Identifier は crypto/x509 が公開鍵から作る。
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	enc, nonce, err := l.KEK.Seal(keyDER, id)
	if err != nil {
		return nil, err
	}
	err = l.DB.InsertCA(ctx, db.CA{ID: id, Kind: kind, Tenant: tenant, CertDER: der, KeyEnc: enc, KeyNonce: nonce,
		KEKID: l.KEK.ID(), Status: db.StatusActive, NotAfter: cert.NotAfter, CreatedAt: now})
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// load は CA の証明書と、復号した鍵を返す。
func (l *Local) load(ctx context.Context, id string) (*x509.Certificate, crypto.Signer, error) {
	c, err := l.DB.CA(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return l.decode(c)
}

func (l *Local) decode(c db.CA) (*x509.Certificate, crypto.Signer, error) {
	cert, err := x509.ParseCertificate(c.CertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("CA %s: certificate: %w", c.ID, err)
	}
	if c.KEKID != l.KEK.ID() {
		return nil, nil, fmt.Errorf("CA %s: the key is encrypted with another KEK (%s, not %s)", c.ID, c.KEKID, l.KEK.ID())
	}
	keyDER, err := l.KEK.Open(c.KeyEnc, c.KeyNonce, c.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("CA %s: %w", c.ID, err)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	clear(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("CA %s: key: %w", c.ID, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("CA %s: the key cannot sign", c.ID)
	}
	return cert, s, nil
}

// SignCertificate は CA caID の鍵で証明書に署名する。
func (l *Local) SignCertificate(ctx context.Context, caID string, tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	ca, key, err := l.load(ctx, caID)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// CreateCRL は CA caID の鍵で CRL に署名する。
func (l *Local) CreateCRL(ctx context.Context, caID string, tmpl *x509.RevocationList) ([]byte, error) {
	ca, key, err := l.load(ctx, caID)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, key)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}
	return der, nil
}

// ErrKEKMismatch は、KEK が DB の記録と合わないことを表す（起動しない。§6.2）。
var ErrKEKMismatch = errors.New("the KEK does not match the database")

// Check は起動のときの確認を行う（§6.2）。KEK の識別子を DB の記録と比べ（初めてなら記録する）、すべての CA の鍵を
// 復号して証明書の公開鍵と合うことを確かめる。確かめた CA の数を返す。
func (l *Local) Check(ctx context.Context) (int, error) {
	id, ok, err := l.DB.Setting(ctx, db.SettingKEKID)
	if err != nil {
		return 0, err
	}
	cas, err := l.DB.CAs(ctx)
	if err != nil {
		return 0, err
	}
	switch {
	case !ok && len(cas) > 0:
		return 0, fmt.Errorf("%w: the database has CAs but no KEK id", ErrKEKMismatch)
	case !ok:
		if err := l.DB.SetSetting(ctx, db.SettingKEKID, l.KEK.ID()); err != nil {
			return 0, err
		}
	case id != l.KEK.ID():
		return 0, fmt.Errorf("%w: the database expects KEK %s but the file is KEK %s", ErrKEKMismatch, id, l.KEK.ID())
	}
	for _, c := range cas {
		cert, key, err := l.decode(c)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrKEKMismatch, err)
		}
		pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(cert.PublicKey) {
			return 0, fmt.Errorf("CA %s: the key does not match the certificate", c.ID)
		}
	}
	return len(cas), nil
}

// Rekey は、すべての CA の鍵を新しい KEK で暗号化し直し、KEK の識別子を書き換える（1 つのトランザクション。§6.3）。
// 本CA を止めてから行う。入れ替えた CA の数を返す。
func (l *Local) Rekey(ctx context.Context, next *kek.KEK) (int, error) {
	if _, err := l.Check(ctx); err != nil {
		return 0, err
	}
	cas, err := l.DB.CAs(ctx)
	if err != nil {
		return 0, err
	}
	err = l.DB.Tx(ctx, func(tx *sql.Tx) error {
		for _, c := range cas {
			plain, err := l.KEK.Open(c.KeyEnc, c.KeyNonce, c.ID)
			if err != nil {
				return fmt.Errorf("CA %s: %w", c.ID, err)
			}
			enc, nonce, err := next.Seal(plain, c.ID)
			clear(plain)
			if err != nil {
				return err
			}
			if err := db.RekeyCA(ctx, tx, c.ID, enc, nonce, next.ID()); err != nil {
				return err
			}
		}
		return db.SetSettingTx(ctx, tx, db.SettingKEKID, next.ID())
	})
	if err != nil {
		return 0, fmt.Errorf("rekey: %w", err)
	}
	return len(cas), nil
}
