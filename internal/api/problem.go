package api

import (
	"encoding/json/v2"
	"net/http"

	"github.com/oyaguma3/radsec-ca/internal/ca"
)

// ProblemDetails の cause のうち、ca の誤り（ca.Cause*）のほかに API で使うもの（設計概要 §9.1）。
const (
	causeIdempotencyConflict = "IDEMPOTENCY_CONFLICT"
	causeSystemFailure       = "SYSTEM_FAILURE"
)

type invalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// problem はエラー応答（ProblemDetails。application/problem+json）。
type problem struct {
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail,omitempty"`
	Cause         string         `json:"cause,omitempty"`
	InvalidParams []invalidParam `json:"invalidParams,omitempty"`
}

func newProblem(status int, cause, detail string) *problem {
	return &problem{Title: http.StatusText(status), Status: status, Cause: cause, Detail: detail}
}

func badRequest(param, reason string) *problem {
	p := newProblem(http.StatusBadRequest, ca.CauseValidation, reason)
	p.InvalidParams = []invalidParam{{Param: param, Reason: reason}}
	return p
}

func (p *problem) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	json.MarshalWrite(w, p)
}

// statusOf は ca の誤りの符号から HTTP のステータスを決める。
func statusOf(cause string) int {
	switch cause {
	case ca.CauseCANotFound, ca.CauseCertNotFound, ca.CauseCRLNotFound:
		return http.StatusNotFound
	case ca.CauseCAExists, ca.CauseCADisabled, ca.CauseFingerprintInUse:
		return http.StatusConflict
	case ca.CauseNameReserved, ca.CauseKeyTypeUnsupported, ca.CauseCSRInvalid, ca.CauseCRLInvalid, ca.CauseCRLRequired,
		ca.CauseTenantOnlyNotConfirmed, ca.CauseNoCRLNotAccepted:
		return http.StatusUnprocessableEntity
	}
	return http.StatusBadRequest
}

// fail は誤りを応答にする。ca の誤りは理由の符号つきで返し、それ以外は記録して詳細を伏せた 500 を返す。
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := ca.AsError(err); ok {
		p := newProblem(statusOf(e.Cause), e.Cause, e.Msg)
		if e.Param != "" {
			p.InvalidParams = []invalidParam{{Param: e.Param, Reason: e.Msg}}
		}
		p.write(w)
		return
	}
	h.Log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	newProblem(http.StatusInternalServerError, causeSystemFailure, "").write(w)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.MarshalWrite(w, v)
}
