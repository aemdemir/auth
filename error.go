package auth

import (
	"errors"
	"fmt"
)

// error codes.
const (
	EINVALID       = "invalid"
	EUNAUTHORIZED  = "unauthorized"
	EFORBIDDEN     = "forbidden"
	ENOTFOUND      = "not_found"
	ECONFLICT      = "conflict"
	EUNPROCESSABLE = "unprocessable"
	EINTERNAL      = "internal"
)

// Error represents an application-specific error.
type Error struct {
	Code    string
	Message string
	Detail  map[string]string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("application error: code=%s message=%s", e.Code, e.Message)
}

func ErrorCode(err error) string {
	var e *Error
	if err == nil {
		return ""
	} else if errors.As(err, &e) {
		return e.Code
	}
	return EINTERNAL
}

func ErrorMessage(err error) string {
	var e *Error
	if err == nil {
		return ""
	} else if errors.As(err, &e) {
		return e.Message
	}
	return "an unexpected error occurred"
}

func ErrorDetail(err error) map[string]string {
	var e *Error
	if err == nil {
		return nil
	} else if errors.As(err, &e) {
		return e.Detail
	}
	return nil
}
