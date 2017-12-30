// Package totp implements Time-Based One Time Password(RFC 6238).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
var digitPow = []int{
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
}

// TOTP is a configuration for Time-Based One Time Password(RFC 6238)
type TOTP struct {
	Algorithm string
	Digits    int
	Period    int
	Secret    []byte
}

// Option is a functional option for TOTP constructor.
type Option func(c *TOTP) error

// Algorithm returns a functional option for the TOTP algorithm.
//
// Currently "sha1", "sha256" and "sha512" are supported.
//
// The default value is "sha1".
func Algorithm(alg string) Option {
	return func(t *TOTP) error {
		switch alg {
		case "sha1", "sha256", "sha512":
			t.Algorithm = alg
			return nil
		default:
			return fmt.Errorf("hash algorithm [%s] is not supported", alg)
		}
	}
}

// Digits returns a functional option for the TOTP digits parameter
// that determines how long of a one-time passcode.
//
// The default value is 6.
func Digits(digits int) Option {
	return func(totp *TOTP) error {
		if digits <= 0 || digits >= len(digitPow) {
			return fmt.Errorf("digits [%d] is not supported", digits)
		}
		totp.Digits = digits
		return nil
	}
}

// Period returns a functional option for the TOTP period parameter
// that defines a period that a TOTP code will be valid for, in seconds.
//
// The default value is 30.
func Period(period int) Option {
	return func(totp *TOTP) error {
		if period <= 0 {
			return fmt.Errorf("period [%d] is not positive", period)
		}
		totp.Period = period
		return nil
	}
}

// Secret returns a functional option for the TOTP secret parameter.
//
// If omitted, it is automatically generated.
func Secret(secret []byte) Option {
	return func(totp *TOTP) error {
		totp.Secret = secret
		return nil
	}
}

// New creates a new TOTP configuration
func New(options ...Option) (*TOTP, error) {
	totp := &TOTP{
		Algorithm: "sha1",
		Digits:    6,
		Period:    30,
	}
	for _, apply := range options {
		err := apply(totp)
		if err != nil {
			return nil, err
		}
	}
	if totp.Secret == nil {
		secret := make([]byte, hashLength(totp.Algorithm))
		_, err := rand.Read(secret)
		if err != nil {
			return nil, fmt.Errorf("not enough secure random stream: %v", err)
		}
		totp.Secret = secret
	}

	return totp, nil
}

// GenerateCode generates a TOTP code using the current time.
func (totp *TOTP) GenerateCode() string {
	return totp.GenerateCodeAt(time.Now())
}

// GenerateCodeAt generates a TOTP code using a specified time.
func (totp *TOTP) GenerateCodeAt(t time.Time) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()/int64(totp.Period)))
	h := hmac.New(hashFunc(totp.Algorithm), totp.Secret)
	h.Write(b)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	code := int(binary.BigEndian.Uint32(sum[offset:]) & 0x7FFFFFFF)
	return truncatedStringCode(code, totp.Digits)
}

// ValidateCode validates a TOTP code using the current time.
func (totp *TOTP) ValidateCode(code string) bool {
	return totp.ValidateCodeAt(code, time.Now())
}

// ValidateCodeAt validates a TOTP code using a specified time.
func (totp *TOTP) ValidateCodeAt(code string, t time.Time) bool {
	return totp.GenerateCodeAt(t) == code
}

// URI returns the OTP URI as a string.
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (totp *TOTP) URI(issuer, account string) string {
	v := url.Values{
		"secret": []string{b32.EncodeToString(totp.Secret)},
		"issuer": []string{issuer},
	}
	if totp.Algorithm != "sha1" {
		v.Set("algorithm", totp.Algorithm)
	}
	if totp.Digits != 6 {
		v.Set("digits", strconv.Itoa(totp.Digits))
	}
	if totp.Period != 30 {
		v.Set("period", strconv.Itoa(totp.Period))
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     account,
		RawQuery: v.Encode(),
	}

	return u.String()
}

func truncatedStringCode(code, digits int) string {
	code %= digitPow[digits]
	ret := strconv.Itoa(code)
	if len(ret) == digits {
		return ret
	}
	return strings.Repeat("0", digits-len(ret)) + ret
}

func hashLength(alg string) int {
	switch alg {
	case "sha1":
		return 20
	case "sha256":
		return 32
	case "sha512":
		return 64
	default:
		panic(fmt.Errorf("hash algorithm [%s] is not supported", alg))
	}
}

func hashFunc(alg string) func() hash.Hash {
	switch alg {
	case "sha1":
		return sha1.New
	case "sha256":
		return sha256.New
	case "sha512":
		return sha512.New
	default:
		panic(fmt.Errorf("hash algorithm [%s] is not supported", alg))
	}
}
