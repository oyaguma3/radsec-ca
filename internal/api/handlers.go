package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
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
}

// crlInfo は最新の CRL の要約。
type crlInfo struct {
	Number     int64     `json:"number"`
	ThisUpdate time.Time `json:"thisUpdate"`
	NextUpdate time.Time `json:"nextUpdate"`
}

func (h *Handler) caJSON(r *http.Request, c db.CA, issued map[string]int) (caJSON, error) {
	cert, err := x509.ParseCertificate(c.CertDER)
	if err != nil {
		return caJSON{}, err
	}
	out := caJSON{ID: c.ID, Kind: c.Kind, Tenant: c.Tenant, Status: c.Status, Subject: cert.Subject.String(), NotAfter: c.NotAfter.UTC(),
		CreatedAt: c.CreatedAt.UTC(), Certificate: string(ca.CertPEM(c.CertDER)), CRLError: h.CA.CRLErrors()[c.ID], Issued: issued[c.ID]}
	if !c.DisabledAt.IsZero() {
		out.DisabledAt = c.DisabledAt.UTC()
	}
	latest, err := h.DB.LatestCRL(r.Context(), c.ID)
	switch {
	case err == nil:
		out.CRL = &crlInfo{Number: latest.Number, ThisUpdate: latest.ThisUpdate.UTC(), NextUpdate: latest.NextUpdate.UTC()}
	case !errors.Is(err, db.ErrNotFound):
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
	cas, err := h.DB.CAs(r.Context())
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

func (h *Handler) createCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant string `json:"tenant"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	c, err := h.CA.CreateTenantCA(r.Context(), actor(r), req.Tenant)
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
	latest, err := h.DB.LatestCRL(r.Context(), c.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		CAID       string    `json:"caId"`
		Number     int64     `json:"number"`
		ThisUpdate time.Time `json:"thisUpdate"`
		NextUpdate time.Time `json:"nextUpdate"`
		CRL        string    `json:"crl"`
	}{c.ID, latest.Number, latest.ThisUpdate.UTC(), latest.NextUpdate.UTC(), string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: latest.DER}))})
}

// certJSON は証明書の応答。
type certJSON struct {
	Serial        string    `json:"serial"`
	CAID          string    `json:"caId"`
	Profile       string    `json:"profile"`
	Tenant        string    `json:"tenant"`
	AP            string    `json:"ap,omitempty"`
	Edge          string    `json:"edge,omitempty"`
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
	out := certJSON{Serial: c.Serial, CAID: c.CAID, Profile: c.Profile, Tenant: c.Tenant, AP: c.AP, Edge: c.Edge, CN: c.CN, SANDNS: c.SANDNS,
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
		CSR     string `json:"csr"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	got, err := h.CA.Issue(r.Context(), actor(r), ca.IssueRequest{Profile: req.Profile,
		Material: ca.Material{Tenant: req.Tenant, AP: req.AP, Edge: req.Edge}, CSR: []byte(req.CSR)})
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
	f := db.CertFilter{Tenant: q.Get("tenant"), Profile: q.Get("profile"), AP: q.Get("ap"), Edge: q.Get("edge"), Status: q.Get("status"), Limit: 100}
	for param, v := range map[string]string{"tenant": f.Tenant, "ap": f.AP, "edge": f.Edge} {
		if v != "" && !names.ValidSlug(v) {
			badRequest(param, "must follow the naming rule").write(w)
			return
		}
	}
	switch f.Profile {
	case "", db.ProfileAPClient, db.ProfileProbeClient, db.ProfileTenantServer:
	default:
		badRequest("profile", "must be ap-client, probe-client or tenant-server").write(w)
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
