package auth

import (
	"errors"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Name         NullString `json:"name"`
	Active       bool       `json:"active"`
	Version      int        `json:"-"`
	Created      time.Time  `json:"created"`
	Updated      time.Time  `json:"updated"`
	PasswordHash []byte     `json:"-"`
}

func (u User) MatchPassword(password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		case errors.Is(err, bcrypt.ErrHashTooShort): // in case of hash is nil
			return false, nil
		}
		return false, err
	}
	return true, nil
}

type Email struct {
	UserID   int       `json:"user_id"`
	Address  string    `json:"address"`
	Primary  bool      `json:"primary"`
	Verified bool      `json:"verified"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

type Account struct {
	UserID         int       `json:"user_id"`
	ProviderName   string    `json:"provider_name"`
	ProviderUserID string    `json:"provider_user_id"`
	Created        time.Time `json:"created"`
}

//
// Inputs
//

// SignupInput defines fields to complete signup.
type SignupInput struct {
	Email    string
	Username string
	Name     string
	Password string
}

func (s SignupInput) IsPrimaryEmail() bool {
	return true
}
func (s SignupInput) HashPassword() ([]byte, error) {
	return hashPassword(s.Password)
}
func (s SignupInput) Validate(v *validator) {
	ValidateEmail(v, s.Email)
	ValidateUsername(v, s.Username)
	validateName(v, s.Name)
	ValidatePassword(v, s.Password)
}

type SigninInput struct {
	Email    string
	Password string
}

func (s SigninInput) Validate(v *validator) {
	ValidateEmail(v, s.Email)
	ValidatePassword(v, s.Password)
}

type SigninSocialInput struct {
	Username string
	Email    NullString
	Name     NullString
	Account  AccountInput
}

func (s SigninSocialInput) PasswordHash() []byte {
	return nil
}
func (s SigninSocialInput) IsPrimaryEmail(isNewUser bool) bool {
	return isNewUser
}
func (s SigninSocialInput) Validate(v *validator) {
	ValidateUsername(v, s.Username)
	if s.Email.Valid {
		ValidateEmail(v, s.Email.String)
	}
	if s.Name.Valid {
		validateName(v, s.Name.String)
	}
	s.Account.Validate(v)
}

type AccountInput struct {
	ProviderName   string
	ProviderUserID string
}

func (a AccountInput) Validate(v *validator) {
	v.Check(notEmpty(a.ProviderName), "provider_name", "must be provided")
	v.Check(notEmpty(a.ProviderUserID), "provider_user_id", "must be provided")
}

type LinkUserAccountInput struct {
	Token   TokenInput
	Account AccountInput
}

func (l LinkUserAccountInput) Validate(v *validator, meta TokenMeta) {
	l.Token.Validate(v, meta)
	l.Account.Validate(v)
}

type ResetPasswordInput struct {
	Token    TokenInput
	Password string
}

func (r ResetPasswordInput) HashPassword() ([]byte, error) {
	return hashPassword(r.Password)
}
func (r ResetPasswordInput) Validate(v *validator, meta TokenMeta) {
	r.Token.Validate(v, meta)
	ValidatePassword(v, r.Password)
}

type UpdatePasswordInput struct {
	UserID      int
	OldPassword string
	NewPassword string
}

func (u UpdatePasswordInput) HashPassword() ([]byte, error) {
	return hashPassword(u.NewPassword)
}
func (u UpdatePasswordInput) Validate(v *validator) {
	ValidatePassword(v, u.NewPassword)
}

//
// Combining
//

type UserEmail struct {
	User
	Email Email `json:"email"`
}

type UserSignin struct {
	UserEmail
	Token string `json:"token"`
}

type UserSigninSocial struct {
	User
	Token string `json:"token"`
}

type UserSettings struct {
	User
	Emails   []Email   `json:"emails"`
	Accounts []Account `json:"accounts"`
}

//
// Helpers
//

const (
	numchars = "0123456789"
)

var (
	seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func RandomUsername() string {
	b := make([]byte, 10)
	for i := range b {
		b[i] = numchars[seededRand.Intn(len(numchars))]
	}
	return "user_" + string(b)
}

func hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 12)
}
