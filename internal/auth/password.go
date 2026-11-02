package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters: OWASP minimum recommendation (19 MiB, 2 passes, 1 lane).
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16

	// MinPasswordLength follows NIST SP 800-63B for memorised secrets
	// chosen without composition rules.
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

// ErrWeakPassword describes a password policy violation. Code is stable
// and translated by the UI.
type ErrWeakPassword struct{ Code, Reason string }

func (e ErrWeakPassword) Error() string { return e.Reason }

// ValidatePassword enforces the password policy.
func ValidatePassword(password, username string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLength:
		return ErrWeakPassword{"password_too_short", fmt.Sprintf("the password must have at least %d characters", MinPasswordLength)}
	case n > MaxPasswordLength:
		return ErrWeakPassword{"password_too_long", fmt.Sprintf("the password cannot exceed %d characters", MaxPasswordLength)}
	case strings.EqualFold(password, username):
		return ErrWeakPassword{"password_equals_username", "the password cannot be the username"}
	case strings.TrimSpace(password) == "":
		return ErrWeakPassword{"password_blank", "the password cannot be blank"}
	}
	return nil
}

func weak(field string, err error) InputError {
	var w ErrWeakPassword
	if errors.As(err, &w) {
		return InputError{Field: field, Code: w.Code, Message: w.Reason}
	}
	return InputError{Field: field, Code: "invalid", Message: err.Error()}
}

// HashPassword returns an argon2id PHC string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("invalid password hash")

// VerifyPassword checks password against a PHC string in constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var mem uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil || mem == 0 || t == 0 || p == 0 || mem > 1<<20 || t > 10 {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// GeneratePassword returns a random temporary password for bootstrap.
func GeneratePassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	// Rejection sampling avoids modulo bias.
	limit := byte(256 - 256%len(alphabet))
	out := make([]byte, 0, 20)
	buf := make([]byte, 1)
	for len(out) < cap(out) {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		if buf[0] < limit {
			out = append(out, alphabet[int(buf[0])%len(alphabet)])
		}
	}
	return string(out)
}
