package oauthserver

import (
	"reflect"
	"time"
)

func ValidateLoginCommit[A any](auth AuthorizationTransaction, consent ConsentSession[A], now time.Time) error {
	if !auth.ConsumedAt.IsZero() {
		return ErrConsumed
	}
	if !auth.ExpiresAt.After(now) {
		return ErrExpired
	}
	if consent.Client.ID != auth.ClientID || consent.Client.RedirectURI != auth.RedirectURI || consent.State != auth.State || consent.PKCEChallenge != auth.PKCEChallenge || consent.Resource != auth.Resource {
		return ErrBinding
	}
	if consent.Principal.Subject == "" || !consent.AllowedScopes.IsSubsetOf(auth.RequestedScopes) || !consent.ExpiresAt.After(now) {
		return ErrInvalid
	}
	return nil
}

func ValidateConsentCommit[A any](consent ConsentSession[A], commit ConsentCommit[A], now time.Time) error {
	if !consent.ConsumedAt.IsZero() {
		return ErrConsumed
	}
	if !consent.ExpiresAt.After(now) {
		return ErrExpired
	}
	if commit.Decision == ConsentDecisionDeny {
		if commit.Code.Digest != (CredentialDigest{}) {
			return ErrInvalid
		}
		return nil
	}
	if commit.Decision != ConsentDecisionApprove {
		return ErrInvalid
	}
	code := commit.Code
	if code.Digest == (CredentialDigest{}) || code.ClientID != consent.Client.ID || code.RedirectURI != consent.Client.RedirectURI || code.State != consent.State || code.PKCEChallenge != consent.PKCEChallenge || code.Resource != consent.Resource || !reflect.DeepEqual(code.Principal, consent.Principal) || !code.Scopes.IsSubsetOf(consent.AllowedScopes) || !code.ExpiresAt.After(now) {
		return ErrBinding
	}
	return nil
}

func ValidateCodeExchangeCommit[A any](code AuthorizationCodeRecord[A], commit CodeExchangeCommit[A], now time.Time) error {
	if !code.ConsumedAt.IsZero() {
		return ErrConsumed
	}
	if !code.ExpiresAt.After(now) {
		return ErrExpired
	}
	if commit.Refresh == nil {
		return ErrInvalid
	}
	refresh := commit.Refresh
	if refresh.Digest == (CredentialDigest{}) || refresh.FamilyID == "" || refresh.Generation != 0 || refresh.ClientID != code.ClientID || !reflect.DeepEqual(refresh.Principal, code.Principal) || refresh.Resource != code.Resource || refresh.Scopes.String() != code.Scopes.String() || !refresh.ExpiresAt.After(now) || !refresh.ConsumedAt.IsZero() || !refresh.RevokedAt.IsZero() {
		return ErrBinding
	}
	return nil
}

func ValidateRefreshRotation[A any](current RefreshGrant[A], rotation RefreshRotation[A], now time.Time) error {
	if current.FamilyID != rotation.FamilyID || current.Generation != rotation.Generation {
		return ErrBinding
	}
	if !current.RevokedAt.IsZero() {
		return ErrRevoked
	}
	if !current.ConsumedAt.IsZero() {
		return ErrConsumed
	}
	if !current.ExpiresAt.After(now) {
		return ErrExpired
	}
	next := rotation.Successor
	if next.Digest == (CredentialDigest{}) || next.FamilyID != current.FamilyID || next.Generation != current.Generation+1 || next.ClientID != current.ClientID || next.Principal.Subject != current.Principal.Subject || next.Resource != current.Resource || !next.Scopes.IsSubsetOf(current.Scopes) || !next.ExpiresAt.Equal(current.ExpiresAt) || !next.ConsumedAt.IsZero() || !next.RevokedAt.IsZero() {
		return ErrBinding
	}
	return nil
}
