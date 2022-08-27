package handler

import (
	"fmt"
	"net/http"

	"github.com/aemdemir/auth"
	"github.com/gorilla/mux"
	"github.com/markbates/goth/gothic"
	"github.com/rs/zerolog"
)

type Config struct {
	SocialSigninRedirectURL    string
	LinkUserAccountRedirectURL string
}

type Handler struct {
	service auth.Service
	logger  zerolog.Logger
	config  Config
}

func New(service auth.Service, logger zerolog.Logger, config Config) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
		config:  config,
	}
}

// Signup registers a new user.
//
// Method: POST
// URL:    /api/v1/auth/signup
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	err := h.service.Signup(r.Context(), auth.SignupInput{
		Email:    req.Email,
		Username: req.Username,
		Name:     req.Name,
		Password: req.Password,
	})
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusAccepted, Map{"message": "an email will be sent to you containing verification instructions"})
}

// Signin logs in users.
//
// Method: POST
// URL:    /api/v1/auth/signin
func (h *Handler) Signin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	user, err := h.service.Signin(r.Context(), auth.SigninInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"user": user.UserEmail, "token": user.Token})
}

// SigninSocialBegin starts oauth authentication.
//
// Method: GET
// URL:    /api/v1/auth/{provider}
func (h *Handler) SigninSocialBegin(w http.ResponseWriter, r *http.Request) {
	ses, err := gothic.Store.New(r, "_login_session")
	if err != nil {
		Error(w, r, err)
		return
	}

	action, err := queryStr(r, "action")
	if err != nil {
		Error(w, r, err)
		return
	}
	if err := validAction(action); err != nil {
		Error(w, r, err)
		return
	}

	ses.Values["action"] = action
	if action == "link" {
		tkn, err := queryStr(r, "confirmation_token")
		if err != nil {
			Error(w, r, err)
			return
		}
		ses.Values["confirmation_token"] = tkn
	}

	err = ses.Save(r, w)
	if err != nil {
		Error(w, r, err)
		return
	}

	gothic.BeginAuthHandler(w, r)
}

// SigninSocialComplete is called by the provider, and it completes the authentication process.
//
// Method: GET
// URL:    /api/v1/auth/{provider}/callback
func (h *Handler) SigninSocialComplete(w http.ResponseWriter, r *http.Request) {
	othUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		Error(w, r, err)
		return
	}

	session, err := gothic.Store.Get(r, "_login_session")
	if err != nil {
		Error(w, r, err)
		return
	}

	action, err := sessionStr(session.Values, "action")
	if err != nil {
		Error(w, r, err)
		return
	}
	if err := validAction(action); err != nil {
		Error(w, r, err)
		return
	}

	if action == "link" {
		tkn, err := sessionStr(session.Values, "confirmation_token")
		if err != nil {
			Error(w, r, err)
			return
		}
		err = h.service.LinkUserAccount(r.Context(), auth.LinkUserAccountInput{
			Token: auth.TokenInput{
				Text: tkn,
			},
			Account: auth.AccountInput{
				ProviderName:   othUser.Provider,
				ProviderUserID: othUser.UserID,
			},
		})
		if err != nil {
			Error(w, r, err)
			return
		}
		http.Redirect(w, r, h.config.LinkUserAccountRedirectURL, http.StatusFound)
		return
	}

	user, err := h.service.SigninSocial(r.Context(), auth.SigninSocialInput{
		Username: auth.RandomUsername(),
		Email:    auth.NewNullString(othUser.Email),
		Name:     auth.NewNullString(othUser.Name),
		Account: auth.AccountInput{
			ProviderName:   othUser.Provider,
			ProviderUserID: othUser.UserID,
		},
	})
	if err != nil {
		Error(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s?token=%s", h.config.SocialSigninRedirectURL, user.Token), http.StatusFound)
}

// SendVerificationEmail sends verification email to the given email address.
//
// Method: POST
// URL:    /api/v1/auth/resend
func (h *Handler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	err := h.service.SendVerificationEmail(r.Context(), req.Email)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusAccepted, Map{"message": "an email will be sent to you containing verification instructions"})
}

// VerifyEmail verifies the email associated with given token.
//
// Method: POST
// URL:    /api/v1/auth/verify
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	err := h.service.VerifyEmail(r.Context(), auth.TokenInput{
		Text: req.Token,
	})
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"message": "email has been verified successfully"})
}

// SendPasswordResetEmail sends password reset email to the given email address.
//
// Method: POST
// URL:    /api/v1/auth/forget
func (h *Handler) SendPasswordResetEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	err := h.service.SendPasswordResetEmail(r.Context(), req.Email)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusAccepted, Map{"message": "an email will be sent to you containing password reset instructions"})
}

// ResetPassword resets password for the user associated with the given token.
//
// Method: POST
// URL:    /api/v1/auth/reset
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	err := h.service.ResetPassword(r.Context(), auth.ResetPasswordInput{
		Token: auth.TokenInput{
			Text: req.Token,
		},
		Password: req.Password,
	})
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"message": "password has been changed successfully"})
}

// UserConfirmation makes sure that the user confirms the action he/she is
// about to perform. If so, it returns a confirmation token.
//
// Method: POST
// URL:    /api/v1/auth/confirm
func (h *Handler) UserConfirmation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	u := ctxGetUser(r)
	token, err := h.service.UserConfirmation(r.Context(), u.ID, req.Password)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"token": token})
}

// AddEmail adds a new email address for a user.
//
// Method: POST
// URL:    /api/v1/emails
func (h *Handler) AddEmail(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Email string `json:"email"`
	}{}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	u := ctxGetUser(r)
	err := h.service.AddEmail(r.Context(), u.ID, req.Email)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusAccepted, Map{"message": "an email will be sent to you containing verification instructions"})
}

// UpdatePrimaryEmail updates a user's primary email address.
//
// Method: PUT
// URL:    /api/v1/emails/primary
func (h *Handler) UpdatePrimaryEmail(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Email string `json:"email"`
	}{}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	u := ctxGetUser(r)
	err := h.service.UpdatePrimaryEmail(r.Context(), u.ID, req.Email)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"message": "primary email has been changed successfully"})
}

// GetUserSettings returns a user's settings.
//
// Method: GET
// URL:    /api/v1/users/me/settings
func (h *Handler) GetUserSettings(w http.ResponseWriter, r *http.Request) {
	u := ctxGetUser(r)
	user, err := h.service.GetUserSettings(r.Context(), u.ID)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"user": user})
}

// UpdateUsername updates a user's username.
//
// Method: PUT
// URL:    /api/v1/users/me/username
func (h *Handler) UpdateUsername(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Username string `json:"username"`
	}{}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	u := ctxGetUser(r)
	err := h.service.UpdateUsername(r.Context(), u.ID, req.Username)
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"message": "username has been changed successfully"})
}

// UpdatePassword updates a user's password.
//
// Method: PUT
// URL:    /api/v1/users/me/password
func (h *Handler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	req := struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}{}
	if err := readRequest(w, r, &req); err != nil {
		Error(w, r, err)
		return
	}

	u := ctxGetUser(r)
	err := h.service.UpdatePassword(r.Context(), auth.UpdatePasswordInput{
		UserID:      u.ID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		Error(w, r, err)
		return
	}

	Response(w, r, http.StatusOK, Map{"message": "password has been changed successfully"})
}

//
// Routes
//

func (h *Handler) SetRoutes(r *mux.Router) {
	// auth
	r.HandleFunc("/api/v1/auth/{provider}", h.SigninSocialBegin).Methods("GET")
	r.HandleFunc("/api/v1/auth/{provider}/callback", h.SigninSocialComplete).Methods("GET")
	r.HandleFunc("/api/v1/auth/signup", h.Signup).Methods("POST")
	r.HandleFunc("/api/v1/auth/signin", h.Signin).Methods("POST")
	r.HandleFunc("/api/v1/auth/resend", h.SendVerificationEmail).Methods("POST")
	r.HandleFunc("/api/v1/auth/verify", h.VerifyEmail).Methods("POST")
	r.HandleFunc("/api/v1/auth/forget", h.SendPasswordResetEmail).Methods("POST")
	r.HandleFunc("/api/v1/auth/reset", h.ResetPassword).Methods("POST")
	r.HandleFunc("/api/v1/auth/confirm", h.RequireUser(h.UserConfirmation)).Methods("POST")

	// email
	r.HandleFunc("/api/v1/emails", h.RequireUser(h.AddEmail)).Methods("POST")
	r.HandleFunc("/api/v1/emails/primary", h.RequireUser(h.UpdatePrimaryEmail)).Methods("PUT")

	// user
	r.HandleFunc("/api/v1/users/me/settings", h.RequireUser(h.GetUserSettings)).Methods("GET")
	r.HandleFunc("/api/v1/users/me/username", h.RequireUser(h.UpdateUsername)).Methods("PUT")
	r.HandleFunc("/api/v1/users/me/password", h.RequireUser(h.UpdatePassword)).Methods("PUT")
}

//
// Helpers
//

func validAction(action string) error {
	if action != "signin" && action != "link" {
		return &auth.Error{Code: auth.EINVALID, Message: "invalid action"}
	}
	return nil
}

func sessionStr(values map[any]any, key string) (string, error) {
	v, ok := values[key]
	if !ok {
		return "", &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("session value '%s' is not found", key)}
	}
	s, ok := v.(string)
	if !ok {
		return "", &auth.Error{
			Code:    auth.EINVALID,
			Message: fmt.Sprintf("session value '%s' must be string", key)}
	}
	return s, nil
}
