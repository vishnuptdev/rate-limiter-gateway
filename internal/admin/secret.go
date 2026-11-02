package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// pbkdf2Iterations is the work factor for new password hashes. It is a var
// (not a const) only so tests can lower it for speed; production code never
// changes it. Verification always uses the iteration count stored in the hash.
var pbkdf2Iterations = 600000

const (
	pbkdf2SaltLen = 16
	pbkdf2KeyLen  = 32
	hashScheme    = "pbkdf2_sha256"

	minPasswordLen = 12   // runes
	maxPasswordLen = 1024 // bytes; bounds hashing work and request size

	// maxStoredIterations bounds the work an attacker-controlled (or corrupt)
	// auth.json could force on a verification.
	maxStoredIterations = 10_000_000
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const lowerAlnum = "0123456789abcdefghijklmnopqrstuvwxyz"

// randomFrom returns n characters drawn uniformly from alphabet using
// crypto/rand with rejection sampling (no modulo bias).
func randomFrom(alphabet string, n int) string {
	if len(alphabet) == 0 || len(alphabet) > 256 {
		panic("bad alphabet")
	}
	limit := 256 - (256 % len(alphabet)) // accept bytes < limit
	out := make([]byte, 0, n)
	buf := make([]byte, n+16)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic(fmt.Sprintf("crypto/rand failed: %v", err)) // never happens on supported platforms
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out)
}

func randomBase62(n int) string { return randomFrom(base62Alphabet, n) }

// randomToken returns a base64url string of n random bytes.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// checkPasswordPolicy enforces the password policy (>= 12 characters).
func checkPasswordPolicy(pw string) error {
	if len(pw) > maxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordLen)
	}
	if utf8.RuneCountInString(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	return nil
}

// hashPassword returns "pbkdf2_sha256$<iter>$<b64salt>$<b64hash>"
// (unpadded standard base64).
func hashPassword(pw string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	iter := pbkdf2Iterations
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return hashScheme + "$" + strconv.Itoa(iter) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(dk), nil
}

var errBadHash = errors.New("malformed password hash")

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func parseHash(encoded string) (iter int, salt, dk []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return 0, nil, nil, errBadHash
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > maxStoredIterations {
		return 0, nil, nil, errBadHash
	}
	if salt, err = decodeB64(parts[2]); err != nil || len(salt) < 8 {
		return 0, nil, nil, errBadHash
	}
	if dk, err = decodeB64(parts[3]); err != nil || len(dk) < 16 || len(dk) > 64 {
		return 0, nil, nil, errBadHash
	}
	return iter, salt, dk, nil
}

// verifyPassword reports whether pw matches encoded, in constant time with
// respect to the derived key.
func verifyPassword(encoded, pw string) bool {
	if len(pw) > maxPasswordLen {
		return false
	}
	iter, salt, want, err := parseHash(encoded)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
