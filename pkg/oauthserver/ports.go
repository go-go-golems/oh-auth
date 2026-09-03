package oauthserver

import (
	"context"
	"time"
)

type Clock interface{ Now() time.Time }

type SecretSource interface {
	NewClientID() (ClientID, error)
	NewTransactionToken() (TransactionToken, error)
	NewConsentToken() (ConsentToken, error)
	NewAuthorizationCode() (AuthorizationCode, error)
	NewRefreshToken() (RefreshToken, error)
	NewRefreshFamilyID() (RefreshFamilyID, error)
}

type ScopePolicy[A any] interface {
	AvailableScopes(context.Context, Principal[A], Resource) (ScopeSet, error)
}

type PrincipalRevalidator[A any] interface {
	Revalidate(context.Context, Subject) (Revalidation[A], error)
}

type RevalidationStatus uint8

const (
	RevalidationUnknown RevalidationStatus = iota
	RevalidationEligible
	RevalidationIneligible
)

type Revalidation[A any] struct {
	Status    RevalidationStatus
	Principal Principal[A]
}

type AuditEvent struct {
	Time       time.Time
	Operation  string
	Outcome    string
	Subject    Subject
	ClientID   ClientID
	Resource   ResourceID
	Scopes     ScopeSet
	ReasonCode string
	RequestID  string
	// Cause is available only to the in-process audit sink for diagnostics. Sinks
	// must never serialize credentials, request bodies, or authorization headers.
	Cause error
}

type AuditSink interface {
	Record(context.Context, AuditEvent)
}

type Store[A any] interface {
	RegisterClient(context.Context, Client, StatePolicy) error
	GetClient(context.Context, ClientID) (Client, error)
	TouchClient(context.Context, ClientID, time.Time) error
	CreateAuthorization(context.Context, AuthorizationTransaction, StatePolicy) error
	GetAuthorization(context.Context, CredentialDigest) (AuthorizationTransaction, error)
	CommitLogin(context.Context, LoginCommit[A], StatePolicy) error
	GetConsent(context.Context, CredentialDigest) (ConsentSession[A], error)
	CommitConsent(context.Context, ConsentCommit[A], StatePolicy) (ConsentCommitResult, error)
	GetCodeForExchange(context.Context, CodeExchangeBinding) (AuthorizationCodeRecord[A], error)
	CommitCodeExchange(context.Context, CodeExchangeCommit[A], StatePolicy) error
	GetRefreshGrant(context.Context, CredentialDigest) (RefreshGrant[A], error)
	CommitRefreshRotation(context.Context, RefreshRotation[A], StatePolicy) error
	RevokeRefreshFamily(context.Context, RefreshFamilyID, time.Time) error
	Prune(context.Context, StatePolicy) (PruneStats, error)
	Counts(context.Context) (StateCounts, error)
}

type LoginCommit[A any] struct {
	TransactionDigest CredentialDigest
	Consent           ConsentSession[A]
}

type ConsentCommit[A any] struct {
	ConsentDigest CredentialDigest
	Code          AuthorizationCodeRecord[A]
	Decision      ConsentDecision
}

type ConsentCommitResult struct {
	RedirectURI string
}

type CodeExchangeBinding struct {
	Digest       CredentialDigest
	ClientID     ClientID
	RedirectURI  RedirectURI
	CodeVerifier string
}

type CodeExchangeCommit[A any] struct {
	CodeDigest CredentialDigest
	Refresh    *RefreshGrant[A]
}

type RefreshRotation[A any] struct {
	CurrentDigest CredentialDigest
	FamilyID      RefreshFamilyID
	Generation    uint64
	Successor     RefreshGrant[A]
}

type PruneStats struct {
	Clients        int
	Authorizations int
	Consents       int
	Codes          int
	RefreshGrants  int
}

type StateCounts struct {
	Clients        int
	Authorizations int
	Consents       int
	Codes          int
	RefreshGrants  int
}

type LoginStarter interface {
	AuthorizationURL(context.Context, LoginContext) (string, error)
}

type ClaimProvider[A any] interface {
	ExtraClaims(context.Context, Principal[A]) (map[string]any, error)
}

type TokenService[A any] interface {
	TokenIssuer() string
	IssueAccessToken(context.Context, AccessGrant[A]) (IssuedAccessToken, error)
	VerifyAccessToken(context.Context, string, ResourceID) (VerifiedAccessToken, error)
	JWKS(context.Context) (JWKS, error)
}

type JWKS struct {
	Keys []map[string]any `json:"keys"`
}
