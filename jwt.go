package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrExpiredToken          = errors.New("jwt: token is expired")
	ErrBeforeIssuedToken     = errors.New("jwt: before issued token")
	ErrInvalidToken          = errors.New("jwt: invalid token")
	ErrIssuerMismatchedToken = errors.New("jwt: issuer mismatched token")
	ErrUnexpectedKeyType     = errors.New("jwt: unexpected key type")
	ErrInvalidPrivateKey     = errors.New("jwt: invalid private key")
	ErrInvalidPublicKey      = errors.New("jwt: invalid public key")
)

// Payload holds the custom fields of jwt
type Payload struct {
	Salt  string `json:"salt,omitempty"`
	Scope string `json:"scope,omitempty"`

	ID     int64          `json:"id,omitempty"`
	IP     string         `json:"ip,omitempty"`
	Values map[string]any `json:"values,omitempty"`
}

// HasScope reports whether the payload has specified scope
func (p *Payload) HasScope(scope string) bool {
	return p.Scope == "*" || strings.Contains(p.Scope, scope)
}

// Claims represents all the fields of jwt
type Claims struct {
	jwt.StandardClaims
	Payload Payload `json:"payload"`
}

// Valid checks whether the claims is valid
func (c Claims) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if c.VerifyExpiresAt(now, true) == false {
		vErr.Inner = ErrExpiredToken
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if c.VerifyIssuedAt(now, false) == false {
		vErr.Inner = ErrBeforeIssuedToken
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
		vErr.Inner = ErrInvalidToken
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// Verifier used to verify token
type Verifier struct {
	ecdsaPubkey *ecdsa.PublicKey
	keyId       string
}

// NewVerifier creates a Verifier
func NewVerifier(filename, keyId string) (*Verifier, error) {
	key, err := loadPublicKey(filename)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		ecdsaPubkey: key,
		keyId:       keyId,
	}, nil
}

// Verify verifies the token and returns parsed claims
func (v *Verifier) Verify(issuer, token string) (*Claims, error) {
	var claims = new(Claims)
	_, err := jwt.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		kid, ok := tok.Header["kid"]
		if !ok || kid == nil {
			return nil, jwt.ErrInvalidKey
		}
		if s, ok := kid.(string); !ok || s != v.keyId {
			return nil, jwt.ErrInvalidKey
		}
		return v.ecdsaPubkey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims.VerifyIssuer(issuer, true) == false {
		return nil, ErrIssuerMismatchedToken
	}
	return claims, nil
}

// Signer used to sign and verify token
type Signer struct {
	Verifier
	ecdsaKey *ecdsa.PrivateKey
}

// NewSigner creates a Signer
func NewSigner(filename, keyId string) (*Signer, error) {
	key, err := loadPrivateKey(filename)
	if err != nil {
		return nil, err
	}
	return &Signer{
		Verifier: Verifier{
			ecdsaPubkey: &key.PublicKey,
			keyId:       keyId,
		},
		ecdsaKey: key,
	}, nil
}

// Sign signs the claims as a token string
func (s *Signer) Sign(claims *Claims) (string, error) {
	var tok = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = s.keyId
	return tok.SignedString(s.ecdsaKey)
}

func loadPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(bytes)
}

func parsePrivateKey(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, ErrInvalidPrivateKey
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pk := key.(type) {
	case *ecdsa.PrivateKey:
		return pk, nil
	default:
		return nil, ErrUnexpectedKeyType
	}
}

func loadPublicKey(filename string) (*ecdsa.PublicKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(bytes)
}

func parsePublicKey(bytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, ErrInvalidPublicKey
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pk := key.(type) {
	case *ecdsa.PublicKey:
		return pk, nil
	default:
		return nil, ErrUnexpectedKeyType
	}
}
