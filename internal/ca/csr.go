package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

// maxCSRBytes は受け付ける CSR（PEM）の大きさの上限（§5.3）。
const maxCSRBytes = 16 << 10

// ParseCSR は PEM の CSR を 1 つだけ読み、自己署名を確かめて、公開鍵を返す（§5.3）。
// 使うのは公開鍵だけで、Subject・SAN・拡張の要求はすべて無視する（好きな SAN を書いた CSR による成りすましを防ぐ）。
// 受け付ける鍵は ECDSA P-256 / P-384、RSA 2048〜4096 ビット。
func ParseCSR(data []byte) (crypto.PublicKey, error) {
	if len(data) > maxCSRBytes {
		return nil, newError(CauseCSRInvalid, "csr", "CSR が大きすぎます（%d バイトまで）", maxCSRBytes)
	}
	block, rest := pem.Decode(bytes.TrimSpace(data))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, newError(CauseCSRInvalid, "csr", "PEM の CSR（CERTIFICATE REQUEST）を 1 つだけ与えてください")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, newError(CauseCSRInvalid, "csr", "CSR が読めません: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, newError(CauseCSRInvalid, "csr", "CSR の署名が正しくありません")
	}
	if err := checkKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr.PublicKey, nil
}

func checkKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n >= 2048 && n <= 4096 {
			return nil
		}
	}
	return newError(CauseKeyTypeUnsupported, "csr", "使えない鍵です（ECDSA P-256 / P-384、RSA 2048〜4096 ビットだけ）")
}

// PubKeySHA256 は公開鍵（SubjectPublicKeyInfo の DER）の SHA-256 の 16 進（記録に残す。§5.3）。
func PubKeySHA256(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
