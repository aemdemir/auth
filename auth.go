package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

type Service interface {
	Signup(ctx context.Context, signup SignupInput) error
	Signin(ctx context.Context, signin SigninInput) (*UserSignin, error)
	SigninSocial(ctx context.Context, signin SigninSocialInput) (*UserSigninSocial, error)
	LinkUserAccount(ctx context.Context, link LinkUserAccountInput) error
	SendVerificationEmail(ctx context.Context, address string) error
	VerifyEmail(ctx context.Context, token TokenInput) error
	SendPasswordResetEmail(ctx context.Context, address string) error
	ResetPassword(ctx context.Context, reset ResetPasswordInput) error
	UserConfirmation(ctx context.Context, uid int, password string) (string, error)
	AddEmail(ctx context.Context, uid int, address string) error
	UpdatePrimaryEmail(ctx context.Context, uid int, address string) error
	GetUserSettings(ctx context.Context, uid int) (*UserSettings, error)
	UpdateUsername(ctx context.Context, uid int, username string) error
	UpdatePassword(ctx context.Context, password UpdatePasswordInput) error
	GetUser(ctx context.Context, token TokenInput) (*User, error)
}

//
// Types
//

// NullString wraps sql.NullString to extend its json capabilities.
type NullString struct {
	sql.NullString
}

// NewNullString returns a new NullString based on the s;
// it is not valid if s is empty, otherwise valid.
func NewNullString(s string) NullString {
	return NullString{
		NullString: sql.NullString{String: s, Valid: strings.TrimSpace(s) != ""}}
}

func (s NullString) MarshalJSON() ([]byte, error) {
	if !s.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(s.String)
}

func (s *NullString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		s.Valid = false
		return nil
	}

	err := json.Unmarshal(data, &s.String)
	if err != nil {
		return err
	}

	s.Valid = true
	return nil
}
