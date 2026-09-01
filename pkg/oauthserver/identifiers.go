package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

type ClientID string
type Subject string
type Scope string
type ResourceID string
type RedirectURI string
type TransactionToken string
type ConsentToken string
type AuthorizationCode string
type RefreshToken string
type RefreshFamilyID string
type CredentialDigest [sha256.Size]byte

type PKCEChallenge struct {
	Value  string
	Method string
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

func newIdentifier[T ~string](raw string, name string) (T, error) {
	raw = strings.TrimSpace(raw)
	if !identifierPattern.MatchString(raw) {
		return "", invalidValue(name)
	}
	return T(raw), nil
}

func NewClientID(raw string) (ClientID, error) { return newIdentifier[ClientID](raw, "client id") }
func NewSubject(raw string) (Subject, error)   { return newIdentifier[Subject](raw, "subject") }
func NewScope(raw string) (Scope, error)       { return newIdentifier[Scope](raw, "scope") }
func NewResourceID(raw string) (ResourceID, error) {
	return newURLIdentifier[ResourceID](raw, "resource")
}
func NewRedirectURI(raw string) (RedirectURI, error) {
	return newURLIdentifier[RedirectURI](raw, "redirect uri")
}

func newURLIdentifier[T ~string](raw string, name string) (T, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", invalidValue(name)
	}
	return T(raw), nil
}

func NewTransactionToken(raw string) (TransactionToken, error) {
	return newOpaque[TransactionToken](raw, "transaction token")
}
func NewConsentToken(raw string) (ConsentToken, error) {
	return newOpaque[ConsentToken](raw, "consent token")
}
func NewAuthorizationCode(raw string) (AuthorizationCode, error) {
	return newOpaque[AuthorizationCode](raw, "authorization code")
}
func NewRefreshToken(raw string) (RefreshToken, error) {
	return newOpaque[RefreshToken](raw, "refresh token")
}
func NewRefreshFamilyID(raw string) (RefreshFamilyID, error) {
	return newOpaque[RefreshFamilyID](raw, "refresh family id")
}

func newOpaque[T ~string](raw string, name string) (T, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 16 || len(raw) > 512 || strings.ContainsAny(raw, " \t\r\n") {
		return "", invalidValue(name)
	}
	return T(raw), nil
}

func DigestCredential(raw string) CredentialDigest { return sha256.Sum256([]byte(raw)) }

func NewPKCEChallenge(value, method string) (PKCEChallenge, error) {
	value = strings.TrimSpace(value)
	method = strings.TrimSpace(method)
	if method != "S256" || value == "" {
		return PKCEChallenge{}, invalidValue("PKCE challenge")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return PKCEChallenge{}, invalidValue("PKCE challenge")
	}
	return PKCEChallenge{Value: value, Method: method}, nil
}

func ValidatePKCEVerifier(verifier string) error {
	if len(verifier) < 43 || len(verifier) > 128 || strings.ContainsAny(verifier, " \t\r\n") {
		return invalidValue("PKCE verifier")
	}
	for _, c := range verifier {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", c) {
			return invalidValue("PKCE verifier")
		}
	}
	return nil
}

func (c PKCEChallenge) Verify(verifier string) error {
	if err := ValidatePKCEVerifier(verifier); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != c.Value {
		return ErrBinding
	}
	return nil
}

func invalidValue(name string) error { return &valueError{name: name} }

type valueError struct{ name string }

func (e *valueError) Error() string { return e.name + " is invalid" }
func (e *valueError) Unwrap() error { return ErrInvalid }
