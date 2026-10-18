// Package publish は配布の口（8449。設計概要 §7.3）。CA の証明書と最新の CRL を HTTP で配る。
//
// 中身は署名つきで公開してよい情報なので、クライアント認証はしない（CRL の改ざんは、エッジが CA の証明書で署名を確かめて防ぐ）。
// エッジは 5 分ごとに取りに来るので、ETag を付けて、変わっていなければ 304 で本文を送らない。
package publish

import (
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-ca/internal/db"
	"github.com/oyaguma3/radsec-ca/internal/signer"
)

// Handler は配布の口のハンドラー。
type Handler struct {
	Log *slog.Logger
	DB  *db.DB
}

// Routes は配布の口のルーティングを返す。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca/{file}", h.ca)
	mux.HandleFunc("GET /crl/{file}", h.crl)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	return mux
}

// caID は「<CA の ID>.<拡張子>」のファイルの名前から CA の ID を取り出す。
func caID(file, ext string) (string, bool) {
	id, ok := strings.CutSuffix(file, ext)
	if !ok {
		return "", false
	}
	if _, _, err := signer.ParseCAID(id); err != nil {
		return "", false
	}
	return id, true
}

// serve は ETag と Last-Modified を付けて本文を返す（If-None-Match が合えば 304）。
func serve(w http.ResponseWriter, r *http.Request, etag string, modified time.Time, contentType string, body []byte) {
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Last-Modified", modified.UTC().Format(http.TimeFormat))
	h.Set("Cache-Control", "max-age=60")
	if match := r.Header.Get("If-None-Match"); match != "" {
		for m := range strings.SplitSeq(match, ",") {
			if strings.TrimSpace(m) == etag || strings.TrimSpace(m) == "*" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	h.Set("Content-Type", contentType)
	h.Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func (h *Handler) ca(w http.ResponseWriter, r *http.Request) {
	id, ok := caID(r.PathValue("file"), ".pem")
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := h.DB.CA(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// CA の証明書は変わらないので、ETag は CA の ID と作った時刻から作る。
	etag := fmt.Sprintf(`"%s-%d"`, id, c.CreatedAt.UnixMilli())
	serve(w, r, etag, c.CreatedAt, "application/x-pem-file", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.CertDER}))
}

func (h *Handler) crl(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	der := strings.HasSuffix(file, ".der")
	ext := ".pem"
	if der {
		ext = ".der"
	}
	id, ok := caID(file, ext)
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := h.DB.LatestCRL(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// ETag は CRL の番号と CA の ID から作る（PEM と DER で別の値にする）。
	etag := fmt.Sprintf(`"%s-%d-%s"`, id, c.Number, strings.TrimPrefix(ext, "."))
	if der {
		serve(w, r, etag, c.ThisUpdate, "application/pkix-crl", c.DER)
		return
	}
	serve(w, r, etag, c.ThisUpdate, "application/x-pem-file", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: c.DER}))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.ErrorContext(r.Context(), "publish", "path", r.URL.Path, "error", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
