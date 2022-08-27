package auth

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

type validator struct {
	Errors map[string]string
}

func NewValidator() *validator {
	return &validator{Errors: make(map[string]string)}
}

func (v *validator) Valid() bool {
	return len(v.Errors) == 0
}

func (v *validator) AddError(key, message string) {
	_, exists := v.Errors[key]
	if !exists {
		v.Errors[key] = message
	}
}

func (v *validator) Check(ok bool, key, message string) {
	if !ok {
		v.AddError(key, message)
	}
}

const (
	maxEmailBytes     = 255
	minUsernameLength = 4
	maxUsernameLength = 15
	minNameLength     = 2
	maxNameLength     = 32
	minPasswordLength = 6
	maxPasswordBytes  = 72
)

var (
	usernameRX        = regexp.MustCompile("^[_]*[a-zA-Z0-9]+[a-zA-Z0-9_]*$")
	emailRX           = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	reservedUsernames = []string{"register", "login", "test", "admin", "root"}
)

// in returns true if a specific value is in the list.
func in[T comparable](value T, list ...T) bool {
	for i := range list {
		if value == list[i] {
			return true
		}
	}
	return false
}

// matches returns true if a string value matches a specific regexp pattern.
func matches(value string, rx *regexp.Regexp) bool {
	return rx.MatchString(value)
}

// unique returns true if all values in a slice are unique.
func unique[T comparable](values []T) bool {
	uniques := make(map[T]bool)

	for _, value := range values {
		uniques[value] = true
	}

	return len(values) == len(uniques)
}

// notEmpty returns true if given string s is not empty.
func notEmpty(s string) bool {
	return strings.TrimSpace(s) != ""
}

func ValidateEmail(v *validator, address string) {
	v.Check(notEmpty(address), "email", "must be provided")
	v.Check(len(address) <= maxEmailBytes, "email", fmt.Sprintf("cannot be longer than %d bytes", maxEmailBytes))
	v.Check(matches(address, emailRX), "email", "must be a valid email address")
}

func ValidateUsername(v *validator, username string) {
	v.Check(notEmpty(username), "username", "must be provided")
	v.Check(utf8.RuneCountInString(username) >= minUsernameLength, "username", fmt.Sprintf("cannot be shorter than %d characters", minUsernameLength))
	v.Check(utf8.RuneCountInString(username) <= maxUsernameLength, "username", fmt.Sprintf("cannot be longer than %d characters", maxUsernameLength))
	v.Check(matches(username, usernameRX), "username", "can only contain alphanumeric characters and underscores")
	v.Check(!in(username, reservedUsernames...), "username", "cannot be a reserved name, for example, login, register etc.")
}

func validateName(v *validator, name string) {
	v.Check(notEmpty(name), "name", "must be provided")
	v.Check(utf8.RuneCountInString(name) <= maxNameLength, "name", fmt.Sprintf("cannot be longer than %d characters", maxNameLength))
}

func ValidatePassword(v *validator, password string) {
	v.Check(notEmpty(password), "password", "must be provided")
	v.Check(utf8.RuneCountInString(password) >= minPasswordLength, "password", fmt.Sprintf("cannot be shorter than %d characters", minPasswordLength))
	v.Check(len(password) <= maxPasswordBytes, "password", fmt.Sprintf("cannot be longer than %d bytes", maxPasswordBytes))
}
