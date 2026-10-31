package ca_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/ca/catest"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/kek"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// crlServer は偽の CRL の配布先（ETag を付け、If-None-Match に 304 を返す）。
type crlServer struct {
	*httptest.Server
	mu   sync.Mutex
	body []byte
	code int
	hits int
	cond int
}

func newCRLServer(t *testing.T, body []byte) *crlServer {
	s := &crlServer{body: body, code: 200}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits++
		etag := fmt.Sprintf(`"%x-%d"`, sha256.Sum256(s.body), s.code)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			s.cond++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(s.code)
		w.Write(s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *crlServer) set(body []byte, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.code = body, code
}

func cause(err error) string {
	if e, ok := ca.AsError(err); ok {
		return e.Cause
	}
	return fmt.Sprint(err)
}

func brought(tenant, name string, v *catest.VendorCA, src ca.CRLSource) ca.BroughtRequest {
	return ca.BroughtRequest{Tenant: tenant, Name: name, CertPEM: v.PEM, CRL: src, TenantOnlyConfirmed: true}
}

func TestRegisterBroughtURL(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	root := catest.NewVendorCA(t, "vendor root")
	v := catest.NewIntermediateCA(t, root, "vendor org CA")
	srv := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 7}))
	c, err := svc.RegisterBrought(ctx, ca.Actor{Operator: "d@example.com", Source: db.SourceAPI}, brought("tenant-a", "meraki", v, ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "brought.tenant-a.meraki" || c.Kind != db.KindTenantBrought || c.Tenant != "tenant-a" || c.SelfSigned || c.Fingerprint == "" ||
		c.CRLSource != db.CRLSourceURL || c.TenantOnlyBy != "d@example.com" || c.CRLOKAt.IsZero() || c.CRLNumber != 1 {
		t.Errorf("ca: %+v", c)
	}
	latest, err := d.LatestCRL(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Number != 1 || latest.ExtNumber != "7" {
		t.Errorf("crl: #%d ext %s", latest.Number, latest.ExtNumber)
	}
	// 自己署名の CA は selfSigned。
	v2 := catest.NewVendorCA(t, "vendor self")
	srv2 := newCRLServer(t, catest.CRLPEM(v2.CRL(t, catest.CRLOptions{Number: 1})))
	c2, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "mist", v2, ca.CRLSource{Source: db.CRLSourceURL, URL: srv2.URL}))
	if err != nil {
		t.Fatal(err)
	}
	if !c2.SelfSigned {
		t.Error("self-signed CA is not marked")
	}
	cas, err := d.TenantCAs(ctx, "tenant-a")
	if err != nil || len(cas) != 2 {
		t.Errorf("tenant CAs: %d %v", len(cas), err)
	}
	// Service の Init が持ち込みの CA の鍵を求めない・定期の作り直しの対象にしないことも確かめる。
	if failed := svc.RefreshCRLs(ctx); failed != 0 {
		t.Errorf("RefreshCRLs: %d failed", failed)
	}
	if n, _ := d.LatestCRL(ctx, c.ID); n.Number != 1 {
		t.Errorf("issued-CA refresh touched the brought CRL: #%d", n.Number)
	}
}

func TestRegisterBroughtRejects(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	v := catest.NewVendorCA(t, "vendor")
	srv := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1}))
	ok := ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}
	other := catest.NewVendorCA(t, "other")
	noSign := catest.NewVendorCAWithUsage(t, "no crl sign", x509.KeyUsageCertSign)
	noCert := catest.NewVendorCAWithUsage(t, "no cert sign", x509.KeyUsageCRLSign)
	leaf := func() []byte { // CA でない証明書
		k := catest.Key(t)
		tmpl := &x509.Certificate{SerialNumber: other.Cert.SerialNumber, Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}()
	bad := newCRLServer(t, []byte("not a crl"))
	otherCRL := newCRLServer(t, other.CRL(t, catest.CRLOptions{Number: 1}))
	expired := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1, ThisUpdate: time.Now().Add(-48 * time.Hour), NextUpdate: time.Now().Add(-time.Hour)}))
	future := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1, ThisUpdate: time.Now().Add(time.Hour)}))
	delta := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1, Delta: true}))
	down := newCRLServer(t, nil)
	down.set(nil, 500)
	for _, c := range []struct {
		name string
		req  ca.BroughtRequest
		want string
	}{
		{"bad tenant", brought("Bad", "n", v, ok), ca.CauseValidation},
		{"bad name", brought("t", "a.b", v, ok), ca.CauseValidation},
		{"not confirmed", ca.BroughtRequest{Tenant: "t", Name: "n", CertPEM: v.PEM, CRL: ok}, ca.CauseTenantOnlyNotConfirmed},
		{"no pem", ca.BroughtRequest{Tenant: "t", Name: "n", CertPEM: []byte("x"), CRL: ok, TenantOnlyConfirmed: true}, ca.CauseValidation},
		{"two certs", ca.BroughtRequest{Tenant: "t", Name: "n", CertPEM: append(append([]byte{}, v.PEM...), other.PEM...), CRL: ok, TenantOnlyConfirmed: true}, ca.CauseValidation},
		{"not a CA", ca.BroughtRequest{Tenant: "t", Name: "n", CertPEM: leaf, CRL: ok, TenantOnlyConfirmed: true}, ca.CauseValidation},
		{"no keyCertSign", brought("t", "n", noCert, ca.CRLSource{Source: db.CRLSourceNone}), ca.CauseNoCRLNotAccepted},
		{"no cRLSign", brought("t", "n", noSign, ok), ca.CauseValidation},
		{"unknown source", brought("t", "n", v, ca.CRLSource{Source: "ftp"}), ca.CauseValidation},
		{"bad url", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: "ftp://x/y"}), ca.CauseValidation},
		{"url with user", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: "https://u:p@x/y"}), ca.CauseValidation},
		{"none not accepted", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceNone}), ca.CauseNoCRLNotAccepted},
		{"upload without crl", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceUpload}), ca.CauseCRLRequired},
		{"meraki without key", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceMeraki, MerakiOrgID: "1"}), ca.CauseValidation},
		{"meraki bad org", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceMeraki, MerakiOrgID: "a/b", MerakiAPIKey: "k"}), ca.CauseValidation},
		{"server down", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: down.URL}), ca.CauseCRLInvalid},
		{"broken crl", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: bad.URL}), ca.CauseCRLInvalid},
		{"crl of another CA", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: otherCRL.URL}), ca.CauseCRLInvalid},
		{"expired crl", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: expired.URL}), ca.CauseCRLInvalid},
		{"future crl", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: future.URL}), ca.CauseCRLInvalid},
		{"delta crl", brought("t", "n", v, ca.CRLSource{Source: db.CRLSourceURL, URL: delta.URL}), ca.CauseCRLInvalid},
	} {
		_, err := svc.RegisterBrought(ctx, ca.System, c.req)
		if cause(err) != c.want {
			t.Errorf("%s: %v (want %s)", c.name, err, c.want)
		}
		// 失敗なら何も残さない（CA4）。
		if _, err := d.CA(ctx, "brought.t.n"); !errors.Is(err, db.ErrNotFound) {
			t.Fatalf("%s: left a row: %v", c.name, err)
		}
	}
	// keyCertSign のない CA（CRL なしで了承しても断る）。
	req := brought("t", "n", noCert, ca.CRLSource{Source: db.CRLSourceNone})
	req.NoCRLAccepted = true
	if _, err := svc.RegisterBrought(ctx, ca.System, req); cause(err) != ca.CauseValidation {
		t.Errorf("no keyCertSign: %v", err)
	}
}

func TestBroughtDuplicate(t *testing.T) {
	svc, _ := catest.New(t)
	ctx := t.Context()
	v := catest.NewVendorCA(t, "vendor")
	srv := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1}))
	src := ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", v, src)); err != nil {
		t.Fatal(err)
	}
	// 別のテナントに同じ CA は断る。同じ名前も断る。
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-b", "v", v, src)); cause(err) != ca.CauseFingerprintInUse {
		t.Errorf("same CA in another tenant: %v", err)
	}
	other := catest.NewVendorCA(t, "other")
	osrv := newCRLServer(t, other.CRL(t, catest.CRLOptions{Number: 1}))
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", other, ca.CRLSource{Source: db.CRLSourceURL, URL: osrv.URL})); cause(err) != ca.CauseCAExists {
		t.Errorf("same name: %v", err)
	}
	// 止めた CA は数えない。同じ CA を別のテナントに登録し直せる（CA5）。止めた名前は使えない。
	if err := svc.DisableCA(ctx, ca.System, "brought.tenant-a.v"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", v, src)); cause(err) != ca.CauseCAExists {
		t.Errorf("name of a disabled CA: %v", err)
	}
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-b", "v", v, src)); err != nil {
		t.Errorf("same CA after disable: %v", err)
	}
}

func TestBroughtRefresh(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	v := catest.NewVendorCA(t, "vendor")
	srv := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 5}))
	c, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", v, ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}))
	if err != nil {
		t.Fatal(err)
	}
	// 変わっていなければ 304 で、CRL の連番は進まない。
	if err := svc.RefreshBrought(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if srv.cond != 1 {
		t.Errorf("conditional requests: %d", srv.cond)
	}
	if got, _ := d.LatestCRL(ctx, c.ID); got.Number != 1 {
		t.Errorf("number after 304: %d", got.Number)
	}
	// 新しい CRL は置く。
	srv.set(v.CRL(t, catest.CRLOptions{Number: 6}), 200)
	if err := svc.RefreshBrought(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := d.LatestCRL(ctx, c.ID)
	if got.Number != 2 || got.ExtNumber != "6" {
		t.Errorf("after update: #%d ext %s", got.Number, got.ExtNumber)
	}
	// 番号の後退は断り、今の CRL を残す。失敗の回数を数える。
	srv.set(v.CRL(t, catest.CRLOptions{Number: 4}), 200)
	for i := 1; i <= 3; i++ {
		if err := svc.RefreshBrought(ctx, c.ID); cause(err) != ca.CauseCRLInvalid {
			t.Fatalf("backwards: %v", err)
		}
		cur, _ := d.CA(ctx, c.ID)
		if cur.CRLFailures != i || !strings.Contains(cur.CRLLastError, "backwards") {
			t.Errorf("failures %d: %+v %s", i, cur.CRLFailures, cur.CRLLastError)
		}
	}
	if got, _ := d.LatestCRL(ctx, c.ID); got.ExtNumber != "6" {
		t.Errorf("CRL replaced by an older one: %s", got.ExtNumber)
	}
	cur, _ := d.CA(ctx, c.ID)
	latest, _ := d.LatestCRL(ctx, c.ID)
	if w := ca.CRLWarning(cur, &latest, time.Now()); !strings.Contains(w, "3 回") {
		t.Errorf("warning: %q", w)
	}
	// 成功すると失敗の数を戻す。
	srv.set(v.CRL(t, catest.CRLOptions{Number: 7}), 200)
	if err := svc.RefreshBrought(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	cur, _ = d.CA(ctx, c.ID)
	if cur.CRLFailures != 0 || cur.CRLLastError != "" {
		t.Errorf("after success: %d %s", cur.CRLFailures, cur.CRLLastError)
	}
}

func TestBroughtPeriodicRefresh(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	now := time.Now()
	svc.Now = func() time.Time { return now }
	v := catest.NewVendorCA(t, "vendor")
	srv := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1}))
	c, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", v, ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}))
	if err != nil {
		t.Fatal(err)
	}
	hits := srv.hits
	// 間隔の前は取りに行かない。
	now = now.Add(59 * time.Minute)
	svc.RefreshBroughtCRLs(ctx)
	if srv.hits != hits {
		t.Errorf("fetched before the interval: %d", srv.hits-hits)
	}
	now = now.Add(2 * time.Minute)
	if failed := svc.RefreshBroughtCRLs(ctx); failed != 0 || srv.hits != hits+1 {
		t.Errorf("after the interval: failed %d, hits %d", failed, srv.hits-hits)
	}
	// 止めたら取りに行かず、最新の CRL は残す（CA7）。
	if err := svc.DisableCA(ctx, ca.System, c.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	svc.RefreshBroughtCRLs(ctx)
	if srv.hits != hits+1 {
		t.Errorf("fetched a disabled CA")
	}
	if _, err := d.LatestCRL(ctx, c.ID); err != nil {
		t.Errorf("CRL of a disabled CA: %v", err)
	}
	if err := svc.RefreshBrought(ctx, c.ID); cause(err) != ca.CauseCADisabled {
		t.Errorf("refresh of a disabled CA: %v", err)
	}
}

func TestBroughtUpload(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	v := catest.NewVendorCA(t, "vendor")
	c, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", v, ca.CRLSource{Source: db.CRLSourceUpload, PEM: catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 1}))}))
	if err != nil {
		t.Fatal(err)
	}
	// DER でも PEM でも受ける。
	if err := svc.UploadCRL(ctx, ca.System, c.ID, v.CRL(t, catest.CRLOptions{Number: 2})); err != nil {
		t.Errorf("DER: %v", err)
	}
	if err := svc.UploadCRL(ctx, ca.System, c.ID, catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 3}))); err != nil {
		t.Errorf("PEM: %v", err)
	}
	if got, _ := d.LatestCRL(ctx, c.ID); got.ExtNumber != "3" || got.Number != 3 {
		t.Errorf("latest: %+v", got.ExtNumber)
	}
	if err := svc.UploadCRL(ctx, ca.System, c.ID, []byte("-----BEGIN X509 CRL-----\nx\n-----END X509 CRL-----\n")); cause(err) != ca.CauseCRLInvalid {
		t.Errorf("broken PEM: %v", err)
	}
	if err := svc.RefreshBrought(ctx, c.ID); cause(err) != ca.CauseValidation {
		t.Errorf("refresh of upload: %v", err)
	}
	// url の CA はアップロードを受けない。
	srv := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1}))
	o := catest.NewVendorCA(t, "o")
	srv.set(o.CRL(t, catest.CRLOptions{Number: 1}), 200)
	c2, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "o", o, ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UploadCRL(ctx, ca.System, c2.ID, o.CRL(t, catest.CRLOptions{Number: 2})); cause(err) != ca.CauseValidation {
		t.Errorf("upload to url: %v", err)
	}
	// 発行した CA はアップロードを受けない。
	if _, err := svc.CreateTenantCA(ctx, ca.System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := svc.UploadCRL(ctx, ca.System, "tenant.tenant-a", v.CRL(t, catest.CRLOptions{Number: 2})); cause(err) != ca.CauseValidation {
		t.Errorf("upload to issued: %v", err)
	}
}

func TestBroughtNone(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	// cRLSign のない CA でも、CRL なしなら受ける。
	v := catest.NewVendorCAWithUsage(t, "vendor", x509.KeyUsageCertSign)
	req := brought("tenant-a", "mist", v, ca.CRLSource{Source: db.CRLSourceNone})
	req.NoCRLAccepted = true
	c, err := svc.RegisterBrought(ctx, ca.Actor{Operator: "d@example.com", Source: db.SourceAPI}, req)
	if err != nil {
		t.Fatal(err)
	}
	if c.NoCRLBy != "d@example.com" || c.CRLSource != db.CRLSourceNone {
		t.Errorf("ca: %+v", c)
	}
	if _, err := d.LatestCRL(ctx, c.ID); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("crl: %v", err)
	}
	if w := ca.CRLWarning(c, nil, time.Now()); w != "" {
		t.Errorf("warning: %s", w)
	}
	// cRLSign のない CA を、CRL のある取得先には替えられない。
	srv := newCRLServer(t, nil)
	if _, err := svc.ChangeCRLSource(ctx, ca.System, c.ID, ca.CRLSource{Source: db.CRLSourceURL, URL: srv.URL}, false); cause(err) != ca.CauseValidation {
		t.Errorf("change without cRLSign: %v", err)
	}
}

func TestChangeCRLSource(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	v := catest.NewVendorCA(t, "vendor")
	a := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 1}))
	c, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "v", v, ca.CRLSource{Source: db.CRLSourceURL, URL: a.URL}))
	if err != nil {
		t.Fatal(err)
	}
	// 新しい取得先から取れなければ替えない。
	bad := newCRLServer(t, nil)
	bad.set(nil, 404)
	if _, err := svc.ChangeCRLSource(ctx, ca.System, c.ID, ca.CRLSource{Source: db.CRLSourceURL, URL: bad.URL}, false); cause(err) != ca.CauseCRLInvalid {
		t.Errorf("bad source: %v", err)
	}
	if cur, _ := d.CA(ctx, c.ID); cur.CRLURL != a.URL {
		t.Errorf("source changed by a failure: %s", cur.CRLURL)
	}
	b := newCRLServer(t, v.CRL(t, catest.CRLOptions{Number: 2}))
	got, err := svc.ChangeCRLSource(ctx, ca.System, c.ID, ca.CRLSource{Source: db.CRLSourceURL, URL: b.URL}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.CRLURL != b.URL || got.CRLNumber != 2 {
		t.Errorf("after change: %s #%d", got.CRLURL, got.CRLNumber)
	}
	// none に替えるには了承が要る。替えると記録する。
	if _, err := svc.ChangeCRLSource(ctx, ca.System, c.ID, ca.CRLSource{Source: db.CRLSourceNone}, false); cause(err) != ca.CauseNoCRLNotAccepted {
		t.Errorf("none: %v", err)
	}
	got, err = svc.ChangeCRLSource(ctx, ca.Actor{Operator: "d", Source: db.SourceAPI}, c.ID, ca.CRLSource{Source: db.CRLSourceNone}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.CRLSource != db.CRLSourceNone || got.NoCRLBy != "d" || got.CRLURL != "" {
		t.Errorf("after none: %+v", got)
	}
	// 持ち込みでない CA は替えられない。
	if _, err := svc.CreateTenantCA(ctx, ca.System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeCRLSource(ctx, ca.System, "tenant.tenant-a", ca.CRLSource{Source: db.CRLSourceNone}, true); cause(err) != ca.CauseValidation {
		t.Errorf("issued: %v", err)
	}
}

// merakiServer は偽の Dashboard API。
func merakiServer(t *testing.T, key string, items func() []string, remaining func() int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/organizations/123/wireless/devices/radsec/certificates/authorities/crls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		type item struct {
			ID  string `json:"certificateAuthorityId"`
			CRL string `json:"crl"`
		}
		doc := struct {
			Items []item `json:"items"`
			Meta  struct {
				Counts struct {
					Items struct {
						Total     int `json:"total"`
						Remaining int `json:"remaining"`
					} `json:"items"`
				} `json:"counts"`
			} `json:"meta"`
		}{}
		for i, c := range items() {
			doc.Items = append(doc.Items, item{ID: fmt.Sprint(i), CRL: c})
		}
		doc.Meta.Counts.Items.Remaining = remaining()
		json.MarshalWrite(w, doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBroughtMeraki(t *testing.T) {
	root := catest.NewVendorCA(t, "meraki root")
	v := catest.NewIntermediateCA(t, root, "org RadSec CA")
	other := catest.NewVendorCA(t, "other org CA")
	var items []string
	remaining := 0
	srv := merakiServer(t, "secret-key", func() []string { return items }, func() int { return remaining })
	svc, d := catest.NewWithMeraki(t, srv.URL)
	ctx := t.Context()
	src := ca.CRLSource{Source: db.CRLSourceMeraki, MerakiOrgID: "123", MerakiAPIKey: "secret-key"}
	// 目的の CRL がないときは登録しない。読めない残りがあれば、そう分かるように誤りにする。
	items = []string{string(catest.CRLPEM(other.CRL(t, catest.CRLOptions{Number: 1})))}
	_, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "meraki", v, src))
	if cause(err) != ca.CauseCRLInvalid || !strings.Contains(err.Error(), "no CRL issued") {
		t.Errorf("not found: %v", err)
	}
	remaining = 2
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "meraki", v, src)); err == nil || !strings.Contains(err.Error(), "2 items") {
		t.Errorf("remaining: %v", err)
	}
	remaining = 0
	// 違う API キーは断られ、誤りにキーは出ない。
	wrong := src
	wrong.MerakiAPIKey = "wrong-key"
	if _, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "meraki", v, wrong)); err == nil || strings.Contains(err.Error(), "wrong-key") {
		t.Errorf("wrong key: %v", err)
	}
	// 組織のほかの CA の CRL に混ざっていても、この CA のものを選ぶ。新しいものを選ぶ。
	items = []string{string(catest.CRLPEM(other.CRL(t, catest.CRLOptions{Number: 9}))),
		string(catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 3, ThisUpdate: time.Now().Add(-2 * time.Hour)}))),
		string(catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 4, ThisUpdate: time.Now().Add(-time.Hour)})))}
	c, err := svc.RegisterBrought(ctx, ca.System, brought("tenant-a", "meraki", v, src))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := d.LatestCRL(ctx, c.ID); got.ExtNumber != "4" {
		t.Errorf("chose #%s", got.ExtNumber)
	}
	// API キーは暗号化して持つ。
	if len(c.MerakiKeyEnc) == 0 || strings.Contains(string(c.MerakiKeyEnc), "secret-key") {
		t.Errorf("key: %q", c.MerakiKeyEnc)
	}
	if plain, err := svc.Secrets.OpenMerakiKey(c); err != nil || plain != "secret-key" {
		t.Errorf("open: %q %v", plain, err)
	}
	// KEK の入れ替えで API キーも暗号化し直す。起動の確認も通る。違う KEK では確認が通らない。
	sig := svc.Secrets.(*signer.Local)
	if _, err := sig.Check(ctx); err != nil {
		t.Fatal(err)
	}
	next, _ := kek.New(bytes.Repeat([]byte{9}, kek.Size))
	if _, err := sig.Rekey(ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, err := sig.Check(ctx); !errors.Is(err, signer.ErrKEKMismatch) {
		t.Errorf("old KEK after rekey: %v", err)
	}
	sig.KEK = next
	if _, err := sig.Check(ctx); err != nil {
		t.Errorf("new KEK: %v", err)
	}
	c, _ = d.CA(ctx, c.ID)
	if plain, err := svc.Secrets.OpenMerakiKey(c); err != nil || plain != "secret-key" {
		t.Errorf("open after rekey: %q %v", plain, err)
	}
	// 別の CA の行に移した暗号文は復号できない（AAD）。
	moved := c
	moved.ID = "brought.tenant-b.meraki"
	if _, err := svc.Secrets.OpenMerakiKey(moved); err == nil {
		t.Error("a key moved to another CA was decrypted")
	}
	// 定期の取得で新しい CRL を置く。
	items = []string{string(catest.CRLPEM(v.CRL(t, catest.CRLOptions{Number: 5})))}
	if err := svc.RefreshBrought(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.LatestCRL(ctx, c.ID); got.ExtNumber != "5" {
		t.Errorf("after refresh #%s", got.ExtNumber)
	}
	// 組織の ID を変えないまま替えるときは、キーを省ける（今のキーを使う）。
	if _, err := svc.ChangeCRLSource(ctx, ca.System, c.ID, ca.CRLSource{Source: db.CRLSourceMeraki, MerakiOrgID: "123"}, false); err != nil {
		t.Errorf("change keeping the key: %v", err)
	}
	// 監査ログにキーを残さない。止めるとキーを消す。
	if err := svc.DisableCA(ctx, ca.System, c.ID); err != nil {
		t.Fatal(err)
	}
	cur, _ := d.CA(ctx, c.ID)
	if len(cur.MerakiKeyEnc) != 0 || cur.Status != db.StatusDisabled {
		t.Errorf("after disable: %+v", cur.Status)
	}
	logs, err := d.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", logs), "secret-key") {
		t.Error("the API key is in the audit log")
	}
}

func TestCRLWarningThreshold(t *testing.T) {
	now := time.Now()
	c := db.CA{Kind: db.KindTenantBrought, Status: db.StatusActive, CRLSource: db.CRLSourceURL}
	row := func(life, left time.Duration) *db.CRL {
		return &db.CRL{ThisUpdate: now.Add(left - life), NextUpdate: now.Add(left)}
	}
	for _, x := range []struct {
		life, left time.Duration
		warn       bool
	}{
		{30 * 24 * time.Hour, 4 * 24 * time.Hour, false},
		{30 * 24 * time.Hour, 2 * 24 * time.Hour, true},
		// 有効期間が短い CRL は半分を閾値にする。
		{24 * time.Hour, 13 * time.Hour, false},
		{24 * time.Hour, 11 * time.Hour, true},
		{24 * time.Hour, -time.Hour, true},
	} {
		if got := ca.CRLWarning(c, row(x.life, x.left), now) != ""; got != x.warn {
			t.Errorf("life %v left %v: %v", x.life, x.left, got)
		}
	}
	// 止めた CA には出さない。
	c.Status = db.StatusDisabled
	if ca.CRLWarning(c, row(24*time.Hour, -time.Hour), now) != "" {
		t.Error("warning for a disabled CA")
	}
}

func TestGroupClient(t *testing.T) {
	svc, d := catest.New(t)
	ctx := t.Context()
	if _, err := svc.CreateTenantCA(ctx, ca.System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	csr := catest.CSR(t, catest.Key(t))
	got, err := svc.Issue(ctx, ca.System, ca.IssueRequest{Profile: db.ProfileGroupClient, Material: ca.Material{Tenant: "tenant-a", Group: "unifi-1"}, CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(got.Cert.CertDER)
	if c.Subject.CommonName != "tenant-a-unifi-1" || len(c.URIs) != 1 || c.URIs[0].String() != "urn:example:grp:tenant-a:unifi-1" ||
		len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || got.Cert.CAID != "tenant.tenant-a" || got.Cert.Group != "unifi-1" {
		t.Errorf("cert: %+v %v", c.Subject, c.URIs)
	}
	page, err := d.Certs(ctx, db.CertFilter{Group: "unifi-1"})
	if err != nil || len(page.Certs) != 1 {
		t.Errorf("filter: %d %v", len(page.Certs), err)
	}
	if !c.NotAfter.After(time.Now().AddDate(0, 0, 729)) {
		t.Errorf("not after: %v", c.NotAfter)
	}
	for _, x := range []struct {
		name string
		m    ca.Material
		want string
	}{
		{"probe", ca.Material{Tenant: "tenant-a", Group: "probe"}, ca.CauseNameReserved},
		{"no group", ca.Material{Tenant: "tenant-a"}, ca.CauseValidation},
		{"bad group", ca.Material{Tenant: "tenant-a", Group: "A_B"}, ca.CauseValidation},
		{"with ap", ca.Material{Tenant: "tenant-a", Group: "g", AP: "a"}, ca.CauseValidation},
		{"with edge", ca.Material{Tenant: "tenant-a", Group: "g", Edge: "e"}, ca.CauseValidation},
	} {
		if _, err := svc.Issue(ctx, ca.System, ca.IssueRequest{Profile: db.ProfileGroupClient, Material: x.m, CSR: csr}); cause(err) != x.want {
			t.Errorf("%s: %v", x.name, err)
		}
	}
	// ほかのプロファイルにグループを与えられない。
	if _, err := svc.Issue(ctx, ca.System, ca.IssueRequest{Profile: db.ProfileAPClient, Material: ca.Material{Tenant: "tenant-a", AP: "a", Group: "g"}, CSR: csr}); cause(err) != ca.CauseValidation {
		t.Errorf("ap with group: %v", err)
	}
}
