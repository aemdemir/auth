package handler

import (
	"net/http"

	"github.com/aemdemir/auth"
)

// codes maps auth error codes to http status codes.
var codes = map[string]int{
	auth.EINVALID:       http.StatusBadRequest,
	auth.EUNAUTHORIZED:  http.StatusUnauthorized,
	auth.EFORBIDDEN:     http.StatusForbidden,
	auth.ENOTFOUND:      http.StatusNotFound,
	auth.ECONFLICT:      http.StatusConflict,
	auth.EUNPROCESSABLE: http.StatusUnprocessableEntity,
	auth.EINTERNAL:      http.StatusInternalServerError,
}

func errStatusCode(code string) int {
	if c, ok := codes[code]; ok {
		return c
	}
	return http.StatusInternalServerError
}
