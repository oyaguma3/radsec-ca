package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/certs"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/names"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// caJSON は CA の応答。
type caJSON struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Tenant      string    `json:"tenant,omitempty"`
	Status      string    `json:"status"`
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"notAfter"`
	CreatedAt   time.Time `json:"createdAt"`
	DisabledAt  time.Time `json:"disabledAt,omitzero"`
	Certificate string    `json:"certificate"`
	CRL         *crlInfo  `json:"crl,omitempty"`
	CRLError    string    `json:"crlError,omitempty"`
	Issued      int       `json:"issued"`
	// Fingerprint は CA の証明書の SHA-256。SelfSigned は自己署名か、HasCRL は CRL があるか（エッジの CRLCheck と PartialChain を決める）。
	Fingerprint string `json:"fingerprint"`
	SelfSigned  bool   `json:"selfSigned"`
	HasCRL      bool   `json:"hasCrl"`
	// 持ち込みの CA の CRL の取得先と状態（§19.3）。API キーは返さず、設定済みかだけを返す。
	CRLSource    string     `json:"crlSource"`
	CRLURL       string     `json:"crlUrl,omitempty"`
	MerakiOrgID  string     `json:"merakiOrgId,omitempty"`
	MerakiKeySet bool       `json:"merakiKeySet,omitempty"`
	CRLState     *crlStatus `json:"crlState,omitempty"`
	// CRLWarning は持ち込みの CA の CRL の警告の文（なければ省く）。
	CRLWarning string `json:"crlWarning,omitempty"`
	// テナント専用の確認と CRL なしの了承（§19.2、§19.3）。
	TenantOnlyConfirmedBy string    `json:"tenantOnlyConfirmedBy,omitempty"`
	TenantOnlyConfirmedAt time.Time `json:"tenantOnlyConfirmedAt,omitzero"`
	NoCRLAcceptedBy       string    `json:"noCrlAcceptedBy,omitempty"`
	NoCRLAcceptedAt       time.Time `json:"noCrlAcceptedAt,omitzero"`
}

// crlStatus は持ち込みの CA の CRL の取得の状態。
type crlStatus struct {
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	OKAt      time.Time `json:"okAt,omitzero"`
	Failures  int       `json:"failures"`
	LastError string    `json:"lastError,omitempty"`
}

// crlInfo は最新の CRL の要約。
type crlInfo struct {
	Number     int64     `json:"number"`
	ExtNumber  string    `json:"extNumber,omitempty"`
	ThisUpdate time.Time `json:"thisUpdate"`
	NextUpdate time.Time `json:"nextUpdate"`
}

// utcOrZero は時刻を UTC にする（ゼロ値はそのまま）。
func utcOrZero(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

func (h *Handler) caJSON(r *http.Request, c db.CA, issued map[string]int) (caJSON, error) {
	cert, err := x509.ParseCertificate(c.CertDER)
	if err != nil {
		return caJSON{}, err
	}
	out := caJSON{ID: c.ID, Kind: c.Kind, Tenant: c.Tenant, Status: c.Status, Subject: cert.Subject.String(), NotAfter: c.NotAfter.UTC(),
		CreatedAt: c.CreatedAt.UTC(), Certificate: string(ca.CertPEM(c.CertDER)), CRLError: h.CA.CRLErrors()[c.ID], Issued: issued[c.ID],
		Fingerprint: certs.Fingerprint(cert), SelfSigned: c.SelfSigned, HasCRL: c.CRLSource != db.CRLSourceNone, CRLSource: c.CRLSource,
		CRLURL: c.CRLURL, MerakiOrgID: c.MerakiOrgID, MerakiKeySet: len(c.MerakiKeyEnc) > 0, TenantOnlyConfirmedBy: c.TenantOnlyBy,
		TenantOnlyConfirmedAt: utcOrZero(c.TenantOnlyAt), NoCRLAcceptedBy: c.NoCRLBy, NoCRLAcceptedAt: utcOrZero(c.NoCRLAt)}
	if !c.DisabledAt.IsZero() {
		out.DisabledAt = c.DisabledAt.UTC()
	}
	if c.Kind == db.KindTenantBrought {
		out.CRLState = &crlStatus{CheckedAt: utcOrZero(c.CRLCheckedAt), OKAt: utcOrZero(c.CRLOKAt), Failures: c.CRLFailures, LastError: c.CRLLastError}
	}
	// CRL をやめた CA には、残っている古い CRL を見せない（配布の口と同じ）。
	if c.CRLSource == db.CRLSourceNone {
		return out, nil
	}
	latest, err := h.DB.LatestCRL(r.Context(), c.ID)
	switch {
	case err == nil:
		out.CRL = &crlInfo{Number: latest.Number, ExtNumber: latest.ExtNumber, ThisUpdate: latest.ThisUpdate.UTC(), NextUpdate: latest.NextUpdate.UTC()}
		out.CRLWarning = ca.CRLWarning(c, &latest, h.now())
	case errors.Is(err, db.ErrNotFound):
		out.CRLWarning = ca.CRLWarning(c, nil, h.now())
	default:
		return caJSON{}, err
	}
	return out, nil
}

// status は本CA の状態（§9.3）。
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	cas, err := h.DB.CAs(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	issued, expiring, err := h.DB.CountCerts(r.Context(), h.now().Add(30*24*time.Hour))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := struct {
		Service      string   `json:"service"`
		Version      string   `json:"version"`
		KEKID        string   `json:"kekId"`
		URNPrefix    string   `json:"urnPrefix"`
		DNSDomain    string   `json:"dnsDomain"`
		CAs          []caJSON `json:"cas"`
		ExpiringSoon int      `json:"expiringSoon"`
	}{Service: "radsec-ca", Version: h.Version, KEKID: h.KEKID, URNPrefix: h.CA.URNPrefix, DNSDomain: h.CA.DNSDomain, CAs: []caJSON{}, ExpiringSoon: expiring}
	for _, c := range cas {
		j, err := h.caJSON(r, c, issued)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		j.Certificate = "" // 状態には証明書の本体を入れない
		out.CAs = append(out.CAs, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) listCAs(w http.ResponseWriter, r *http.Request) {
	var cas []db.CA
	var err error
	if tenant := r.URL.Query().Get("tenant"); tenant != "" {
		if !names.ValidSlug(tenant) {
			badRequest("tenant", "must follow the naming rule").write(w)
			return
		}
		cas, err = h.DB.TenantCAs(r.Context(), tenant)
	} else {
		cas, err = h.DB.CAs(r.Context())
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	issued, _, err := h.DB.CountCerts(r.Context(), h.now())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := []caJSON{}
	for _, c := range cas {
		j, err := h.caJSON(r, c, issued)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		items = append(items, j)
	}
	writeJSON(w, http.StatusOK, struct {
		Items []caJSON `json:"items"`
	}{items})
}

// caByPath はパスの CA を返す（なければ 404 CA_NOT_FOUND を書いて false）。
func (h *Handler) caByPath(w http.ResponseWriter, r *http.Request) (db.CA, bool) {
	id := r.PathValue("caId")
	if _, _, err := signer.ParseCAID(id); err != nil {
		h.fail(w, r, &ca.Error{Cause: ca.CauseCANotFound, Param: "caId", Msg: "CA " + id + " はありません"})
		return db.CA{}, false
	}
	c, err := h.DB.CA(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		h.fail(w, r, &ca.Error{Cause: ca.CauseCANotFound, Param: "caId", Msg: "CA " + id + " はありません"})
		return db.CA{}, false
	}
	if err != nil {
		h.fail(w, r, err)
		return db.CA{}, false
	}
	return c, true
}

func (h *Handler) writeCA(w http.ResponseWriter, r *http.Request, status int, c db.CA) {
	issued, _, err := h.DB.CountCerts(r.Context(), h.now())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	j, err := h.caJSON(r, c, issued)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, status, j)
}

func (h *Handler) getCA(w http.ResponseWriter, r *http.Request) {
	if c, ok := h.caByPath(w, r); ok {
		h.writeCA(w, r, http.StatusOK, c)
	}
}

// crlSourceJSON は CRL の取得先の要求（§19.5）。
type crlSourceJSON struct {
	Source       string `json:"source"`
	URL          string `json:"url,omitempty"`
	MerakiOrgID  string `json:"merakiOrgId,omitempty"`
	MerakiAPIKey string `json:"merakiApiKey,omitempty"`
	PEM          string `json:"pem,omitempty"`
}

func (j crlSourceJSON) source() ca.CRLSource {
	return ca.CRLSource{Source: j.Source, URL: j.URL, MerakiOrgID: j.MerakiOrgID, MerakiAPIKey: j.MerakiAPIKey, PEM: []byte(j.PEM)}
}

func (h *Handler) createCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant string `json:"tenant"`
		// Kind が brought なら持ち込みの CA の登録（§19.2）。空ならテナントのクライアントCA の作成。
		Kind                string        `json:"kind"`
		Name                string        `json:"name"`
		CertPEM             string        `json:"certPem"`
		CRL                 crlSourceJSON `json:"crl"`
		TenantOnlyConfirmed bool          `json:"tenantOnlyConfirmed"`
		NoCRLAccepted       bool          `json:"noCrlAccepted"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	var c db.CA
	var err error
	switch req.Kind {
	case "brought":
		c, err = h.CA.RegisterBrought(r.Context(), actor(r), ca.BroughtRequest{Tenant: req.Tenant, Name: req.Name, CertPEM: []byte(req.CertPEM),
			CRL: req.CRL.source(), TenantOnlyConfirmed: req.TenantOnlyConfirmed, NoCRLAccepted: req.NoCRLAccepted})
	case "":
		if req.Name != "" || req.CertPEM != "" || req.CRL != (crlSourceJSON{}) || req.TenantOnlyConfirmed || req.NoCRLAccepted {
			badRequest("kind", "the items of a brought CA need kind brought").write(w)
			return
		}
		c, err = h.CA.CreateTenantCA(r.Context(), actor(r), req.Tenant)
	default:
		badRequest("kind", "must be brought or omitted").write(w)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/cas/"+c.ID)
	h.writeCA(w, r, http.StatusCreated, c)
}

func (h *Handler) disableCA(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caByPath(w, r)
	if !ok {
		return
	}
	if err := h.CA.DisableCA(r.Context(), actor(r), c.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	c, err := h.DB.CA(r.Context(), c.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCA(w, r, http.StatusOK, c)
}

func (h *Handler) getCRL(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caByPath(w, r)
	if !ok {
		return
	}
	noCRL := &ca.Error{Cause: ca.CauseCRLNotFound, Param: "caId", Msg: "CA " + c.ID + " に CRL はありません"}
	if c.CRLSource == db.CRLSourceNone {
		h.fail(w, r, noCRL)
		return
	}
	latest, err := h.DB.LatestCRL(r.Context(), c.ID)
	if errors.Is(err, db.ErrNotFound) {
		h.fail(w, r, noCRL)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		CAID       string    `json:"caId"`
		Number     int64     `json:"number"`
		ExtNumber  string    `json:"extNumber,omitempty"`
		ThisUpdate time.Time `json:"thisUpdate"`
		NextUpdate time.Time `json:"nextUpdate"`
		CRL        string    `json:"crl"`
	}{c.ID, latest.Number, latest.ExtNumber, latest.ThisUpdate.UTC(), latest.NextUpdate.UTC(), string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: latest.DER}))})
}

// putCRL は取得先が upload の CA に CRL を置く（§19.3）。
func (h *Handler) putCRL(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caByPath(w, r)
	if !ok {
		return
	}
	var req struct {
		PEM string `json:"pem"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	if err := h.CA.UploadCRL(r.Context(), actor(r), c.ID, []byte(req.PEM)); err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCurrentCA(w, r, c.ID)
}

// refreshCRL は持ち込みの CA の CRL をすぐ取りに行く（§19.5）。
func (h *Handler) refreshCRL(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caByPath(w, r)
	if !ok {
		return
	}
	if err := h.CA.RefreshBrought(r.Context(), c.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.CA.Audit(r.Context(), actor(r), "ca.crl.refresh", c.ID, nil)
	h.writeCurrentCA(w, r, c.ID)
}

// putCRLSource は持ち込みの CA の CRL の取得先を変える（§19.5）。
func (h *Handler) putCRLSource(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caByPath(w, r)
	if !ok {
		return
	}
	var req struct {
		CRL           crlSourceJSON `json:"crl"`
		NoCRLAccepted bool          `json:"noCrlAccepted"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	if _, err := h.CA.ChangeCRLSource(r.Context(), actor(r), c.ID, req.CRL.source(), req.NoCRLAccepted); err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCurrentCA(w, r, c.ID)
}

// writeCurrentCA は CA を読み直して応答する。
func (h *Handler) writeCurrentCA(w http.ResponseWriter, r *http.Request, id string) {
	c, err := h.DB.CA(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCA(w, r, http.StatusOK, c)
}

// certJSON は証明書の応答。
type certJSON struct {
	Serial        string    `json:"serial"`
	CAID          string    `json:"caId"`
	Profile       string    `json:"profile"`
	Tenant        string    `json:"tenant"`
	AP            string    `json:"ap,omitempty"`
	Edge          string    `json:"edge,omitempty"`
	Group         string    `json:"group,omitempty"`
	CN            string    `json:"cn"`
	SANDNS        []string  `json:"sanDns,omitempty"`
	SANURI        string    `json:"sanUri,omitempty"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	Status        string    `json:"status"`
	RevokedAt     time.Time `json:"revokedAt,omitzero"`
	RevokeReason  string    `json:"revokeReason,omitempty"`
	PubKeySHA256  string    `json:"pubkeySha256"`
	IssuedAt      time.Time `json:"issuedAt"`
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"caCertificate,omitempty"`
}

func (h *Handler) certJSON(c db.Cert) certJSON {
	out := certJSON{Serial: c.Serial, CAID: c.CAID, Profile: c.Profile, Tenant: c.Tenant, AP: c.AP, Edge: c.Edge, Group: c.Group, CN: c.CN, SANDNS: c.SANDNS,
		SANURI: c.SANURI, NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), Status: c.Status(h.now()), RevokeReason: c.RevokeReason,
		PubKeySHA256: c.PubKeySHA256, IssuedAt: c.CreatedAt.UTC(), Certificate: string(ca.CertPEM(c.CertDER))}
	if !c.RevokedAt.IsZero() {
		out.RevokedAt = c.RevokedAt.UTC()
	}
	return out
}

func (h *Handler) issue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile string `json:"profile"`
		Tenant  string `json:"tenant"`
		AP      string `json:"ap"`
		Edge    string `json:"edge"`
		Group   string `json:"group"`
		CSR     string `json:"csr"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	got, err := h.CA.Issue(r.Context(), actor(r), ca.IssueRequest{Profile: req.Profile,
		Material: ca.Material{Tenant: req.Tenant, AP: req.AP, Edge: req.Edge, Group: req.Group}, CSR: []byte(req.CSR)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := h.certJSON(got.Cert)
	out.CACertificate = string(got.CAPEM)
	w.Header().Set("Location", "/certs/"+got.Cert.Serial)
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) certByPath(w http.ResponseWriter, r *http.Request) (db.Cert, bool) {
	serial := r.PathValue("serial")
	c, err := h.DB.Cert(r.Context(), serial)
	if errors.Is(err, db.ErrNotFound) {
		h.fail(w, r, &ca.Error{Cause: ca.CauseCertNotFound, Param: "serial", Msg: "シリアル番号 " + serial + " の証明書はありません"})
		return db.Cert{}, false
	}
	if err != nil {
		h.fail(w, r, err)
		return db.Cert{}, false
	}
	return c, true
}

func (h *Handler) getCert(w http.ResponseWriter, r *http.Request) {
	if c, ok := h.certByPath(w, r); ok {
		writeJSON(w, http.StatusOK, h.certJSON(c))
	}
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	serial := r.PathValue("serial")
	if _, err := h.CA.Revoke(r.Context(), actor(r), serial, req.Reason); err != nil {
		h.fail(w, r, err)
		return
	}
	if c, ok := h.certByPath(w, r); ok {
		writeJSON(w, http.StatusOK, h.certJSON(c))
	}
}

func (h *Handler) listCerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.CertFilter{Tenant: q.Get("tenant"), Profile: q.Get("profile"), AP: q.Get("ap"), Edge: q.Get("edge"), Group: q.Get("group"), Status: q.Get("status"), Limit: 100}
	for param, v := range map[string]string{"tenant": f.Tenant, "ap": f.AP, "edge": f.Edge, "group": f.Group} {
		if v != "" && !names.ValidSlug(v) {
			badRequest(param, "must follow the naming rule").write(w)
			return
		}
	}
	switch f.Profile {
	case "", db.ProfileAPClient, db.ProfileGroupClient, db.ProfileProbeClient, db.ProfileTenantServer:
	default:
		badRequest("profile", "must be ap-client, group-client, probe-client or tenant-server").write(w)
		return
	}
	switch f.Status {
	case "", "valid", "revoked", "expired":
	default:
		badRequest("status", "must be valid, revoked or expired").write(w)
		return
	}
	if v := q.Get("expiresBefore"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			badRequest("expiresBefore", "must be an RFC 3339 date-time").write(w)
			return
		}
		f.ExpiresBefore = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			badRequest("limit", "must be an integer between 1 and 500").write(w)
			return
		}
		f.Limit = n
	}
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			badRequest("after", "must be the next value of the previous page").write(w)
			return
		}
		f.After = n
	}
	page, err := h.DB.Certs(r.Context(), f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := struct {
		Items []certJSON `json:"items"`
		Next  string     `json:"next,omitempty"`
	}{Items: []certJSON{}}
	for _, c := range page.Certs {
		out.Items = append(out.Items, h.certJSON(c))
	}
	if page.Next > 0 {
		out.Next = strconv.FormatInt(page.Next, 10)
	}
	writeJSON(w, http.StatusOK, out)
}
