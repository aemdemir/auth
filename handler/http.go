package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"github.com/aemdemir/auth"
)

var logger zerolog.Logger

func SetLogger(l zerolog.Logger) {
	logger = l
}

type Map map[string]any

func LogError(r *http.Request, err error) {
	logger.Err(err).Str("method", r.Method).Stringer("url", r.URL).Msg("http error")
}

// Error sends an http error response.
func Error(w http.ResponseWriter, r *http.Request, err error) {
	code, message, detail := auth.ErrorCode(err), auth.ErrorMessage(err), auth.ErrorDetail(err)

	if code == auth.EINTERNAL {
		LogError(r, err)
	}

	c := errStatusCode(code)
	v := Map{"error": message}

	if detail != nil {
		v["error_detail"] = detail
	}
	Response(w, r, c, v)
}

// Response sends an http response with the provided v.
func Response(w http.ResponseWriter, r *http.Request, c int, v any) {
	switch r.Header.Get("Accept") {
	case "application/json":
		fallthrough
	default:
		// default to json for convenience.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(c)
		if err := jsonEncode(w, r, v); err != nil {
			LogError(r, fmt.Errorf("sending json response failed: %w", err))
		}
	}
}

// readRequest reads request body and stores the value in the v.
func readRequest(w http.ResponseWriter, r *http.Request, v any) error {
	switch r.Header.Get("Content-Type") {
	case "application/json":
		fallthrough
	default:
		// default to json for convenience.
		return jsonDecode(w, r, v)
	}
}

func queryStr(r *http.Request, key string) (string, error) {
	val := r.URL.Query().Get(key)
	if val == "" {
		return "", &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("query parameter '%s' is not found", key)}
	}
	return val, nil
}

func queryStrDefault(r *http.Request, key string, def string) string {
	val, err := queryStr(r, key)
	if err != nil {
		return def
	}
	return val
}

func queryInt(r *http.Request, key string) (int, error) {
	s, err := queryStr(r, key)
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return -1, &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("query parameter '%s' must be int", key)}
	}
	return val, nil
}

func queryTime(r *http.Request, key, layout string) (time.Time, error) {
	s, err := queryStr(r, key)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("query parameter '%s' is in wrong time format, expected time format '%s'", key, layout)}
	}
	return t, nil
}

func routeStr(r *http.Request, key string) (string, error) {
	val, ok := mux.Vars(r)[key]
	if !ok {
		return "", &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("route parameter '%s' is not found", key)}
	}
	return val, nil
}

func routeInt(r *http.Request, key string) (int, error) {
	s, err := routeStr(r, key)
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return -1, &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("route parameter '%s' must be int", key)}
	}
	return val, nil
}

func jsonEncode(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func jsonDecode(w http.ResponseWriter, r *http.Request, v any) error {
	maxBytes := 1_048_576
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(v)
	if err != nil {
		var (
			errSyntax *json.SyntaxError
			errType   *json.UnmarshalTypeError
			msg       string
		)

		switch {
		case errors.As(err, &errSyntax):
			msg = fmt.Sprintf(
				"body contains badly-formed json (at position %d)",
				errSyntax.Offset)

		case errors.As(err, &errType):
			msg = fmt.Sprintf(
				"body contains incorrect type for field %q (at position %d)",
				errType.Field,
				errType.Offset)

		case strings.HasPrefix(err.Error(), "json: unknown field "):
			msg = fmt.Sprintf(
				"body contains unknown field '%s'",
				strings.TrimPrefix(err.Error(), "json: unknown field "))

		case err.Error() == "http: request body too large":
			msg = fmt.Sprintf("body must not be larger than %d bytes", maxBytes)

		default:
			msg = fmt.Sprintf("body contains badly-formed json: %s", err)
		}

		return &auth.Error{Code: auth.EINVALID, Message: msg}
	}

	if dec.More() {
		return &auth.Error{Code: auth.EINVALID, Message: "body must only contain a single json object"}
	}
	return nil
}

type ctxKey string

const (
	ctxUserKey ctxKey = "user"
)

// ctxSetUser sets a user to the given request's context.
func ctxSetUser(r *http.Request, user *auth.User) *http.Request {
	ctx := context.WithValue(r.Context(), ctxUserKey, user)
	return r.WithContext(ctx)
}

// ctxGetUser retrieves the user from the request context.
// If it doesn't exist we know that it is an unexpected error.
// It's OK to panic in those circumstances.
func ctxGetUser(r *http.Request) *auth.User {
	user, ok := r.Context().Value(ctxUserKey).(*auth.User)
	if !ok {
		panic("missing user value in request context")
	}
	return user
}
