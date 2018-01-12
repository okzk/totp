// Package totp implements Time-Based One Time Password(RFC 6238).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

// Key is a configuration for Time-Based One Time Password(RFC 6238)
type Key struct {
	algorithm string
	digits    int
	period    int
	secret    []byte
}

type key struct {
	Algorithm string `json:"a"`
	Digits    int    `json:"d"`
	Period    int    `json:"p"`
	Secret    []byte `json:"s"`
}

// Encrypter is the interface that wraps the basic Encrypt method
type Encrypter interface {
	Encrypt(msg []byte) ([]byte, error)
}

// Decrypter is the interface that wraps the basic Decrypt method
type Decrypter interface {
	Decrypt(msg []byte) ([]byte, error)
}

// EncDecrypter is the interface that groups the basic Encrypt and Decrypt methods.
type EncDecrypter interface {
	Encrypter
	Decrypter
}

// Option is a functional option for Key constructor.
type Option func(k *Key) error

// Algorithm returns a functional option for the TOTP algorithm.
//
// Currently "sha1", "sha256" and "sha512" are supported.
//
// The default value is "sha1".
func Algorithm(alg string) Option {
	return func(k *Key) error {
		switch alg {
		case "sha1", "sha256", "sha512":
			k.algorithm = alg
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
	return func(k *Key) error {
		if digits <= 0 || digits >= len(digitPow) {
			return fmt.Errorf("digits [%d] is not supported", digits)
		}
		k.digits = digits
		return nil
	}
}

// Period returns a functional option for the TOTP period parameter
// that defines a period that a TOTP code will be valid for, in seconds.
//
// The default value is 30.
func Period(period int) Option {
	return func(k *Key) error {
		if period <= 0 {
			return fmt.Errorf("period [%d] is not positive", period)
		}
		k.period = period
		return nil
	}
}

// Secret returns a functional option for the TOTP secret parameter.
//
// If omitted, it is automatically generated.
func Secret(secret []byte) Option {
	return func(k *Key) error {
		k.secret = secret
		return nil
	}
}

// NewKey creates a new TOTP key
func NewKey(options ...Option) (*Key, error) {
	k := &Key{
		algorithm: "sha1",
		digits:    6,
		period:    30,
	}
	for _, apply := range options {
		err := apply(k)
		if err != nil {
			return nil, err
		}
	}
	if k.secret == nil {
		secret := make([]byte, hashLength(k.algorithm))
		_, err := rand.Read(secret)
		if err != nil {
			return nil, fmt.Errorf("not enough secure random stream: %v", err)
		}
		k.secret = secret
	}

	return k, nil
}

// GenerateCode generates a TOTP code using the current time.
func (k *Key) GenerateCode() string {
	return k.GenerateCodeAt(time.Now())
}

// GenerateCodeAt generates a TOTP code using a specified time.
func (k *Key) GenerateCodeAt(t time.Time) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()/int64(k.period)))
	h := hmac.New(hashFunc(k.algorithm), k.secret)
	h.Write(b)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	code := int(binary.BigEndian.Uint32(sum[offset:]) & 0x7FFFFFFF)
	return truncatedStringCode(code, k.digits)
}

// ValidateCode validates a TOTP code using the current time.
func (k *Key) ValidateCode(code string) bool {
	return k.ValidateCodeAt(code, time.Now())
}

// ValidateCodeAt validates a TOTP code using a specified time.
func (k *Key) ValidateCodeAt(code string, t time.Time) bool {
	return k.GenerateCodeAt(t) == code
}

// URI returns the OTP URI as a string.
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (k *Key) URI(issuer, account string) string {
	v := url.Values{
		"secret": []string{b32.EncodeToString(k.secret)},
		"issuer": []string{issuer},
	}
	if k.algorithm != "sha1" {
		v.Set("algorithm", k.algorithm)
	}
	if k.digits != 6 {
		v.Set("digits", strconv.Itoa(k.digits))
	}
	if k.period != 30 {
		v.Set("period", strconv.Itoa(k.period))
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     account,
		RawQuery: v.Encode(),
	}

	return u.String()
}

// ToEncryptedString converts key to encrypted string
func (k *Key) ToEncryptedString(encrypter Encrypter) (string, error) {
	tmp := key{
		Algorithm: k.algorithm,
		Digits:    k.digits,
		Period:    k.period,
		Secret:    k.secret,
	}
	raw, err := json.Marshal(&tmp)
	if err != nil {
		return "", err
	}
	encrypted, err := encrypter.Encrypt(raw)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// FromEncryptedString decrypts and returns key
func FromEncryptedString(encryptedStr string, decrypter Decrypter) (*Key, error) {
	encrypted, err := base64.URLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, err
	}
	raw, err := decrypter.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	tmp := key{}
	err = json.Unmarshal(raw, &tmp)
	if err != nil {
		return nil, err
	}

	return NewKey(Algorithm(tmp.Algorithm), Digits(tmp.Digits), Period(tmp.Period), Secret(tmp.Secret))
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
