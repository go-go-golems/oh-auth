package oauthserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"
)

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type CryptoSecrets struct{ Reader io.Reader }

func (s CryptoSecrets) reader() io.Reader {
	if s.Reader != nil {
		return s.Reader
	}
	return rand.Reader
}

func (s CryptoSecrets) opaque(makeValue func(string) error) (string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(s.reader(), bytes); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(bytes)
	if err := makeValue(value); err != nil {
		return "", err
	}
	return value, nil
}

func (s CryptoSecrets) NewClientID() (ClientID, error) {
	// Raw base64url may begin with '-' or '_', while ClientID uses the
	// identifier grammar whose first character must be alphanumeric.
	value, err := s.opaque(func(value string) error {
		_, err := NewClientID("c" + value)
		return err
	})
	if err != nil {
		return "", err
	}
	return ClientID("c" + value), nil
}
func (s CryptoSecrets) NewTransactionToken() (TransactionToken, error) {
	value, err := s.opaque(func(value string) error { _, err := NewTransactionToken(value); return err })
	return TransactionToken(value), err
}
func (s CryptoSecrets) NewConsentToken() (ConsentToken, error) {
	value, err := s.opaque(func(value string) error { _, err := NewConsentToken(value); return err })
	return ConsentToken(value), err
}
func (s CryptoSecrets) NewAuthorizationCode() (AuthorizationCode, error) {
	value, err := s.opaque(func(value string) error { _, err := NewAuthorizationCode(value); return err })
	return AuthorizationCode(value), err
}
func (s CryptoSecrets) NewRefreshToken() (RefreshToken, error) {
	value, err := s.opaque(func(value string) error { _, err := NewRefreshToken(value); return err })
	return RefreshToken(value), err
}
func (s CryptoSecrets) NewRefreshFamilyID() (RefreshFamilyID, error) {
	value, err := s.opaque(func(value string) error { _, err := NewRefreshFamilyID(value); return err })
	return RefreshFamilyID(value), err
}

type NopAudit struct{}

func (NopAudit) Record(_ context.Context, _ AuditEvent) {}
