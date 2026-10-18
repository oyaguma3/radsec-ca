package ca

import (
	"errors"
	"fmt"
)

// 誤りの理由の符号（管理API の ProblemDetails の cause。設計概要 §9.1）。
const (
	CauseValidation         = "VALIDATION_ERROR"
	CauseCSRInvalid         = "CSR_INVALID"
	CauseKeyTypeUnsupported = "KEY_TYPE_UNSUPPORTED"
	CauseNameReserved       = "NAME_RESERVED"
	CauseCANotFound         = "CA_NOT_FOUND"
	CauseCAExists           = "CA_EXISTS"
	CauseCADisabled         = "CA_DISABLED"
	CauseCertNotFound       = "CERT_NOT_FOUND"
)

// Error は呼び出し側の誤り（理由の符号と、利用者に見せる文）。
type Error struct {
	Cause string
	// Param は誤りのある項目（なければ空）。
	Param string
	Msg   string
}

func (e *Error) Error() string { return e.Msg }

func newError(cause, param, format string, args ...any) error {
	return &Error{Cause: cause, Param: param, Msg: fmt.Sprintf(format, args...)}
}

// AsError は err が呼び出し側の誤りなら、それを返す。
func AsError(err error) (*Error, bool) { return errors.AsType[*Error](err) }
