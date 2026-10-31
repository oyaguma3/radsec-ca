package web

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/ca"
	"github.com/oyaguma3/radsec-ca/internal/certs"
	"github.com/oyaguma3/radsec-ca/internal/config"
	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/names"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// caRow は CA の一覧の 1 行。
type caRow struct {
	db.CA
	Subject  string
	Issued   int
	CRL      *db.CRL
	CRLError string
	// CRLWarn は nextUpdate までが 3 日を切ったこと（作り直しが止まっている。§7.2）。
	CRLWarn bool
	// BroughtWarn は持ち込みの CA の CRL の警告の文（§19.3）。
	BroughtWarn string
	// Fingerprint は CA の証明書の SHA-256。
	Fingerprint string
}

func (h *Handler) caRows(r *http.Request) ([]caRow, int, error) {
	cas, err := h.DB.CAs(r.Context())
	if err != nil {
		return nil, 0, err
	}
	issued, expiring, err := h.DB.CountCerts(r.Context(), h.Now().Add(30*24*time.Hour))
	if err != nil {
		return nil, 0, err
	}
	errs := h.CA.CRLErrors()
	var rows []caRow
	for _, c := range cas {
		row := caRow{CA: c, Issued: issued[c.ID], CRLError: errs[c.ID]}
		if cert, err := x509.ParseCertificate(c.CertDER); err == nil {
			row.Subject = cert.Subject.String()
			row.Fingerprint = certs.Fingerprint(cert)
		}
		if c.Kind == db.KindTenantBrought {
			row.CRLError = c.CRLLastError
		}
		if c.CRLSource != db.CRLSourceNone {
			crl, err := h.DB.LatestCRL(r.Context(), c.ID)
			switch {
			case err == nil:
				row.CRL = &crl
				if c.Kind == db.KindTenantBrought {
					row.BroughtWarn = ca.CRLWarning(c, &crl, h.Now())
				} else {
					row.CRLWarn = crl.NextUpdate.Sub(h.Now()) < 72*time.Hour
				}
			case !errors.Is(err, db.ErrNotFound):
				return nil, 0, err
			}
		}
		rows = append(rows, row)
	}
	return rows, expiring, nil
}

// homeData はダッシュボード（§10.2）に出す値。
type homeData struct {
	CAs                       []caRow
	ExpiringSoon              int
	KEKID                     string
	Org, URNPrefix, DNSDomain string
	APIEnabled                bool
	// Tenant と Error は、テナントのクライアントCA の作成のフォームの値と誤り。
	Tenant, Error string
}

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	h.renderHome(w, r, http.StatusOK, "", "")
}

func (h *Handler) renderHome(w http.ResponseWriter, r *http.Request, status int, tenant, errMsg string) {
	rows, expiring, err := h.caRows(r)
	if err != nil {
		h.Log.Error("home", "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	h.render(w, r, status, "home", "ダッシュボード", homeData{CAs: rows, ExpiringSoon: expiring, KEKID: h.KEKID, Org: h.CA.Org,
		URNPrefix: h.CA.URNPrefix, DNSDomain: h.CA.DNSDomain, APIEnabled: h.APIEnabled, Tenant: tenant, Error: errMsg})
}

func (h *Handler) caCreate(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	tenant := strings.TrimSpace(r.PostFormValue("tenant"))
	c, err := h.CA.CreateTenantCA(r.Context(), actorFrom(r.Context()), tenant)
	if e, ok := ca.AsError(err); ok {
		h.renderHome(w, r, http.StatusUnprocessableEntity, tenant, e.Msg)
		return
	}
	if err != nil {
		h.Log.Error("create CA", "error", err)
		h.renderError(w, r, http.StatusInternalServerError, "CA を作れませんでした。")
		return
	}
	http.Redirect(w, r, "/cas/"+c.ID, http.StatusSeeOther)
}

// caData は CA の詳細の画面に出す値。
type caData struct {
	caRow
	PEM     string
	Cert    *x509.Certificate
	CRLs    []db.CRL
	Message string
	Error   string
}

func (h *Handler) loadCA(w http.ResponseWriter, r *http.Request) (db.CA, bool) {
	id := r.PathValue("id")
	if _, _, err := signer.ParseCAID(id); err != nil {
		h.renderError(w, r, http.StatusNotFound, "CA が見つかりません。")
		return db.CA{}, false
	}
	c, err := h.DB.CA(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		h.renderError(w, r, http.StatusNotFound, "CA が見つかりません。")
		return db.CA{}, false
	}
	if err != nil {
		h.Log.Error("load CA", "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return db.CA{}, false
	}
	return c, true
}

func (h *Handler) caDetail(w http.ResponseWriter, r *http.Request) {
	h.renderCA(w, r, http.StatusOK, "", "")
}

func (h *Handler) renderCA(w http.ResponseWriter, r *http.Request, status int, msg, errMsg string) {
	c, ok := h.loadCA(w, r)
	if !ok {
		return
	}
	rows, _, err := h.caRows(r)
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	d := caData{Message: msg, Error: errMsg, PEM: string(ca.CertPEM(c.CertDER))}
	for _, row := range rows {
		if row.ID == c.ID {
			d.caRow = row
		}
	}
	d.Cert, _ = x509.ParseCertificate(c.CertDER)
	if d.CRLs, err = h.DB.CRLs(r.Context(), c.ID); err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	h.render(w, r, status, "ca", "CA "+c.ID, d)
}

func (h *Handler) caDownload(w http.ResponseWriter, r *http.Request) {
	if c, ok := h.loadCA(w, r); ok {
		download(w, c.ID+".pem", "application/x-pem-file", ca.CertPEM(c.CertDER))
	}
}

func (h *Handler) crlDownload(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadCA(w, r)
	if !ok {
		return
	}
	n, err := strconv.ParseInt(strings.TrimSuffix(r.PathValue("number"), ".pem"), 10, 64)
	if err != nil {
		h.notFound(w, r)
		return
	}
	crls, err := h.DB.CRLs(r.Context(), c.ID)
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	for _, crl := range crls {
		if crl.Number == n {
			download(w, c.ID+"-"+strconv.FormatInt(n, 10)+".crl.pem", "application/x-pem-file", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.DER}))
			return
		}
	}
	h.notFound(w, r)
}

func (h *Handler) caDisable(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadCA(w, r)
	if !ok {
		return
	}
	err := h.CA.DisableCA(r.Context(), actorFrom(r.Context()), c.ID)
	if e, ok := ca.AsError(err); ok {
		h.renderCA(w, r, http.StatusUnprocessableEntity, "", e.Msg)
		return
	}
	if err != nil {
		h.Log.Error("disable CA", "error", err)
		h.renderCA(w, r, http.StatusInternalServerError, "", "CA を停止できませんでした: "+err.Error())
		return
	}
	if c.Kind == db.KindTenantBrought {
		h.renderCA(w, r, http.StatusOK, "持ち込みの CA を停止しました。CRL の取得を止め、API キーを消しました（最新の CRL は配り続けます）。", "")
		return
	}
	h.renderCA(w, r, http.StatusOK, "CA を停止し、有効な証明書をすべて失効させました（CRL は作り続けます）。", "")
}

// crlRefresh は持ち込みの CA の CRL をすぐ取りに行く（§19.5）。
func (h *Handler) crlRefresh(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadCA(w, r)
	if !ok {
		return
	}
	err := h.CA.RefreshBrought(r.Context(), c.ID)
	if e, ok := ca.AsError(err); ok {
		h.renderCA(w, r, http.StatusUnprocessableEntity, "", e.Msg)
		return
	}
	if err != nil {
		h.Log.Error("refresh CRL", "error", err)
		h.renderCA(w, r, http.StatusInternalServerError, "", "CRL を取りに行けませんでした: "+err.Error())
		return
	}
	h.CA.Audit(r.Context(), actorFrom(r.Context()), "ca.crl.refresh", c.ID, nil)
	h.renderCA(w, r, http.StatusOK, "CRL を取りに行きました。", "")
}

// maxCRLUpload は画面からアップロードできる CRL の大きさの上限。
const maxCRLUpload = 1 << 20

// crlUpload は取得先が upload の CA に CRL を置く（§19.3）。貼り付けた PEM か、PEM・DER のファイルを受ける。
func (h *Handler) crlUpload(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadCA(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCRLUpload+4096)
	if err := r.ParseMultipartForm(maxCRLUpload); err != nil {
		h.renderCA(w, r, http.StatusBadRequest, "", "フォームを読めません（1 MiB まで）。")
		return
	}
	data := []byte(strings.TrimSpace(r.PostFormValue("pem")))
	if file, _, err := r.FormFile("file"); err == nil {
		defer file.Close()
		if b, err := io.ReadAll(file); err == nil && len(b) > 0 {
			data = b
		}
	}
	err := h.CA.UploadCRL(r.Context(), actorFrom(r.Context()), c.ID, data)
	if e, ok := ca.AsError(err); ok {
		h.renderCA(w, r, http.StatusUnprocessableEntity, "", e.Msg)
		return
	}
	if err != nil {
		h.Log.Error("upload CRL", "error", err)
		h.renderCA(w, r, http.StatusInternalServerError, "", "CRL を置けませんでした: "+err.Error())
		return
	}
	h.renderCA(w, r, http.StatusOK, "CRL を置きました。", "")
}

// certsData は証明書の一覧の画面に出す値。
type certsData struct {
	Certs []certRow
	// フィルターの値。
	CA, Tenant, Profile, Status string
	Expiring                    bool
	// Next は続きの URL（なければ空）。
	Next  string
	Error string
}

// certRow は証明書の一覧の 1 行。
type certRow struct {
	db.Cert
	State string
	Soon  bool
}

func (h *Handler) row(c db.Cert) certRow {
	now := h.Now()
	st := c.Status(now)
	return certRow{Cert: c, State: st, Soon: st == "valid" && c.NotAfter.Sub(now) < 30*24*time.Hour}
}

func (h *Handler) certList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := certsData{CA: q.Get("ca"), Tenant: q.Get("tenant"), Profile: q.Get("profile"), Status: q.Get("status"), Expiring: q.Get("expiring") == "1"}
	f := db.CertFilter{CAID: d.CA, Tenant: d.Tenant, Profile: d.Profile, Status: d.Status, Limit: 100}
	if d.Tenant != "" && !names.ValidSlug(d.Tenant) {
		d.Error, f.Tenant = "テナントの名前が正しくありません。", "-"
	}
	switch d.Status {
	case "", "valid", "revoked", "expired":
	default:
		d.Error, f.Status = "状態が正しくありません。", ""
	}
	if d.Expiring {
		f.ExpiresBefore = h.Now().Add(30 * 24 * time.Hour)
	}
	if v := q.Get("after"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			f.After = n
		}
	}
	page, err := h.DB.Certs(r.Context(), f)
	if err != nil {
		h.Log.Error("list certs", "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	for _, c := range page.Certs {
		d.Certs = append(d.Certs, h.row(c))
	}
	if page.Next > 0 {
		next := url.Values{}
		for k, v := range q {
			if k != "after" {
				next[k] = v
			}
		}
		next.Set("after", strconv.FormatInt(page.Next, 10))
		d.Next = "/certs?" + next.Encode()
	}
	h.render(w, r, http.StatusOK, "certs", "証明書", d)
}

// certData は証明書の詳細の画面に出す値。
type certData struct {
	certRow
	PEM        string
	Reasons    []struct{ Value, Label string }
	APIEnabled bool
	Message    string
	Error      string
}

func (h *Handler) renderCert(w http.ResponseWriter, r *http.Request, status int, msg, errMsg string) {
	c, err := h.DB.Cert(r.Context(), r.PathValue("serial"))
	if errors.Is(err, db.ErrNotFound) {
		h.renderError(w, r, http.StatusNotFound, "証明書が見つかりません。")
		return
	}
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	h.render(w, r, status, "cert", "証明書 "+c.Serial, certData{certRow: h.row(c), PEM: string(ca.CertPEM(c.CertDER)),
		Reasons: reasonLabels, APIEnabled: h.APIEnabled, Message: msg, Error: errMsg})
}

func (h *Handler) certDetail(w http.ResponseWriter, r *http.Request) {
	h.renderCert(w, r, http.StatusOK, "", "")
}

func (h *Handler) certDownload(w http.ResponseWriter, r *http.Request) {
	c, err := h.DB.Cert(r.Context(), r.PathValue("serial"))
	if err != nil {
		h.notFound(w, r)
		return
	}
	download(w, c.CN+"-"+c.Serial+".pem", "application/x-pem-file", ca.CertPEM(c.CertDER))
}

func (h *Handler) certRevoke(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	changed, err := h.CA.Revoke(r.Context(), actorFrom(r.Context()), r.PathValue("serial"), r.PostFormValue("reason"))
	if e, ok := ca.AsError(err); ok {
		if e.Cause == ca.CauseCertNotFound {
			h.renderError(w, r, http.StatusNotFound, "証明書が見つかりません。")
			return
		}
		h.renderCert(w, r, http.StatusUnprocessableEntity, "", e.Msg)
		return
	}
	if err != nil {
		h.Log.Error("revoke", "error", err)
		h.renderCert(w, r, http.StatusInternalServerError, "", "失効させられませんでした: "+err.Error())
		return
	}
	msg := "失効させ、CRL を作り直しました。エッジは次の CRL の取得（5 分ごと）で読み直します。"
	if !changed {
		msg = "この証明書はすでに失効しています。"
	}
	h.renderCert(w, r, http.StatusOK, msg, "")
}

// signData は署名の画面に出す値（§10.2）。
type signData struct {
	Profile, Tenant, AP, Edge, CSR string
	Tenants                        []string
	APIEnabled                     bool
	Error                          string
	// Issued は署名の結果（成功したときだけ）。
	Issued *ca.Issued
	PEM    string
	CAPEM  string
}

func (h *Handler) tenants(r *http.Request) []string {
	cas, _ := h.DB.CAs(r.Context())
	var out []string
	for _, c := range cas {
		if c.Kind == db.KindTenantClient && c.Status == db.StatusActive {
			out = append(out, c.Tenant)
		}
	}
	return out
}

func (h *Handler) signForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "sign", "署名", signData{Profile: db.ProfileAPClient, Tenants: h.tenants(r), APIEnabled: h.APIEnabled})
}

func (h *Handler) sign(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	d := signData{Profile: r.PostFormValue("profile"), Tenant: strings.TrimSpace(r.PostFormValue("tenant")), AP: strings.TrimSpace(r.PostFormValue("ap")),
		Edge: strings.TrimSpace(r.PostFormValue("edge")), CSR: r.PostFormValue("csr"), Tenants: h.tenants(r), APIEnabled: h.APIEnabled}
	m := ca.Material{Tenant: d.Tenant}
	if d.Profile == db.ProfileAPClient {
		m.AP = d.AP
	} else {
		m.Edge = d.Edge
	}
	got, err := h.CA.Issue(r.Context(), actorFrom(r.Context()), ca.IssueRequest{Profile: d.Profile, Material: m, CSR: []byte(d.CSR)})
	if e, ok := ca.AsError(err); ok {
		d.Error = e.Msg
		h.render(w, r, http.StatusUnprocessableEntity, "sign", "署名", d)
		return
	}
	if err != nil {
		h.Log.Error("sign", "error", err)
		d.Error = "署名できませんでした: " + err.Error()
		h.render(w, r, http.StatusInternalServerError, "sign", "署名", d)
		return
	}
	d.Issued, d.PEM, d.CAPEM, d.CSR = &got, string(got.CertPEM), string(got.CAPEM), ""
	h.render(w, r, http.StatusOK, "sign", "署名", d)
}

// usersData は利用者の画面に出す値。
type usersData struct {
	Users        []db.User
	InitialAdmin string
	Email, Role  string
	Message      string
	Error        string
}

func (h *Handler) renderUsers(w http.ResponseWriter, r *http.Request, status int, d usersData) {
	us, err := h.DB.Users(r.Context())
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	d.Users, d.InitialAdmin = us, h.InitialAdmin
	if d.Role == "" {
		d.Role = db.RoleViewer
	}
	h.render(w, r, status, "users", "利用者", d)
}

func (h *Handler) userList(w http.ResponseWriter, r *http.Request) {
	h.renderUsers(w, r, http.StatusOK, usersData{})
}

func (h *Handler) userCreate(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	email, role := config.NormalizeEmail(r.PostFormValue("email")), r.PostFormValue("role")
	d := usersData{Email: email, Role: role}
	switch {
	case !config.ValidEmail(email):
		d.Error = "メールアドレスは、英数字と ._- の 64 文字までにしてください。"
	case role != db.RoleAdmin && role != db.RoleViewer:
		d.Error = "役割は admin か viewer にしてください。"
	}
	if d.Error == "" {
		err := h.DB.CreateUser(r.Context(), email, role)
		switch {
		case errors.Is(err, db.ErrConflict):
			d.Error = "この利用者はすでにいます。"
		case err != nil:
			h.Log.Error("create user", "error", err)
			d.Error = "利用者を追加できませんでした。"
		default:
			h.CA.Audit(r.Context(), actorFrom(r.Context()), "user.create", email, map[string]any{"role": role})
			h.renderUsers(w, r, http.StatusOK, usersData{Message: email + " を追加しました。"})
			return
		}
	}
	h.renderUsers(w, r, http.StatusUnprocessableEntity, d)
}

func (h *Handler) userUpdate(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	email, role, enabled := r.PathValue("email"), r.PostFormValue("role"), r.PostFormValue("enabled") == "1"
	if role != db.RoleAdmin && role != db.RoleViewer {
		h.renderUsers(w, r, http.StatusUnprocessableEntity, usersData{Error: "役割は admin か viewer にしてください。"})
		return
	}
	if email == h.InitialAdmin && (role != db.RoleAdmin || !enabled) {
		h.renderUsers(w, r, http.StatusUnprocessableEntity, usersData{Error: "最初の管理者（CA_INITIAL_ADMIN_EMAIL）は、降格・無効にできません。"})
		return
	}
	err := h.DB.UpdateUser(r.Context(), email, role, enabled)
	if errors.Is(err, db.ErrNotFound) {
		h.renderError(w, r, http.StatusNotFound, "利用者が見つかりません。")
		return
	}
	if err != nil {
		h.Log.Error("update user", "error", err)
		h.renderUsers(w, r, http.StatusInternalServerError, usersData{Error: "利用者を変えられませんでした。"})
		return
	}
	h.CA.Audit(r.Context(), actorFrom(r.Context()), "user.update", email, map[string]any{"role": role, "enabled": enabled})
	h.renderUsers(w, r, http.StatusOK, usersData{Message: email + " を変えました。"})
}

// auditData は監査ログの画面に出す値。
type auditData struct {
	Entries []db.AuditEntry
	More    string
}

const auditPage = 100

func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	var before int64
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			h.renderError(w, r, http.StatusBadRequest, "before の値が正しくありません。")
			return
		}
		before = n
	}
	es, err := h.DB.ListAudit(r.Context(), before, auditPage+1)
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	d := auditData{Entries: es}
	if len(es) > auditPage {
		d.Entries = es[:auditPage]
		d.More = "/audit?before=" + strconv.FormatInt(d.Entries[auditPage-1].ID, 10)
	}
	if before > 0 && isHTMX(r) {
		h.renderBlock(w, r, http.StatusOK, "audit", "audit-rows", d)
		return
	}
	h.render(w, r, http.StatusOK, "audit", "監査ログ", d)
}
