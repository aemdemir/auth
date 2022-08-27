package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"math"
	"time"
)

var (
	TokenAuth              = TokenMeta{Scope: "auth", TTL: 30 * 24 * time.Hour, ByteSize: 16}
	TokenConfirmation      = TokenMeta{Scope: "confirmation", TTL: 5 * time.Minute, ByteSize: 5}
	TokenEmailVerification = TokenMeta{Scope: "email_verification", TTL: 3 * 24 * time.Hour, ByteSize: 5}
	TokenPasswordReset     = TokenMeta{Scope: "password_reset", TTL: 1 * time.Hour, ByteSize: 5}
)

// TokenMeta represents the meta data for a token.
//
// ByteSize will determine the length of the token.
// On Base32, 5 bits are used to represent a single character.
// In order to keep the same length across different bytes input,
// blocks of 5 bytes are used (padded if less than 5).
// With some calculations, 5 bytes gives 8 characters,
// and 16 bytes gives 26 characters.
type TokenMeta struct {
	Scope    string
	TTL      time.Duration
	ByteSize int
}

func (t TokenMeta) Length() int {
	return int(math.Ceil(float64(t.ByteSize*8) / float64(5)))
}

func (t TokenMeta) New(userID int, payload string) (*Token, error) {
	bytes := make([]byte, t.ByteSize)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return &Token{
		UserID:  userID,
		Text:    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes),
		Scope:   t.Scope,
		Expiry:  time.Now().Add(t.TTL),
		Payload: NewNullString(payload),
	}, nil
}

type Token struct {
	UserID  int
	Text    string
	Scope   string
	Expiry  time.Time
	Payload NullString
}

func (t Token) HashToken() []byte {
	return hashToken(t.Text)
}

type TokenInput struct {
	Text string
}

func (t TokenInput) HashToken() []byte {
	return hashToken(t.Text)
}
func (t TokenInput) Validate(v *validator, meta TokenMeta) {
	v.Check(notEmpty(t.Text), "token", "must be provided")
	v.Check(len(t.Text) == meta.Length(), "token", "must be in a valid format")
}

//
// Helpers
//

func hashToken(text string) []byte {
	h := sha256.Sum256([]byte(text))
	return h[:]
}
