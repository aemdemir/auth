package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/aemdemir/auth"
)

// Recoverer recovers panics and returns server error.
func (h *Handler) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// This makes Go's HTTP server automatically close the current connection
				// after a response has been sent.
				w.Header().Set("Connection", "close")

				Error(w, r, fmt.Errorf("panic: %s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORS handles the same origin policy.
func (h *Handler) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")

		var (
			origin         = r.Header.Get("Origin")
			trustedOrigins = []string{
				h.config.SocialSigninRedirectURL,
				h.config.LinkUserAccountRedirectURL,
			}
		)

		if origin != "" && len(trustedOrigins) != 0 {
			for i := range trustedOrigins {
				if origin == trustedOrigins[i] {
					w.Header().Set("Access-Control-Allow-Origin", origin)

					// Check if the request is a preflight request.
					// When responding to a preflight request it’s not necessary to include
					// CORS-safe methods (e.g. head, get or post) and headers.
					if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
						// Set the necessary preflight response headers.
						w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, PUT, PATCH, DELETE")
						w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
						w.WriteHeader(http.StatusOK)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// authenticate checks the authorization token.
func (h *Handler) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Authorization")

		header := r.Header.Get("Authorization")
		splits := strings.Split(header, " ")

		if len(splits) != 2 || splits[0] != "Bearer" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			Error(w, r, &auth.Error{Code: auth.EUNAUTHORIZED, Message: "missing authentication token"})
			return
		}

		txt := splits[1]
		user, err := h.service.GetUser(r.Context(), auth.TokenInput{Text: txt})
		if err != nil {
			Error(w, r, err)
			return
		}

		r = ctxSetUser(r, user)
		next.ServeHTTP(w, r)
	}
}

// RequireUser requires an authenticated user.
func (h *Handler) RequireUser(next http.HandlerFunc) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if user := ctxGetUser(r); !user.Active {
			Error(w, r, &auth.Error{Code: auth.EFORBIDDEN, Message: "this user is deactivated"})
			return
		}
		next.ServeHTTP(w, r)
	}

	return h.authenticate(fn)
}
