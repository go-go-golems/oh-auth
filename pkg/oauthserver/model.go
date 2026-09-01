package oauthserver

import (
	"context"
	"time"
)

type Principal[A any] struct {
	Subject              Subject
	DisplayName          string
	Email                string
	AuthorizationVersion int64
	Attributes           A
}

type PrincipalCodec[A any] interface {
	EncodePrincipal(Principal[A]) ([]byte, error)
	DecodePrincipal([]byte) (Principal[A], error)
}

type Resource struct {
	ID              ResourceID
	DisplayName     string
	SupportedScopes ScopeSet
}

type ResourceRegistry interface {
	LookupResource(context.Context, ResourceID) (Resource, error)
	ListResources(context.Context) ([]Resource, error)
}

type ClientTrust string

const (
	ClientTrustUnverified ClientTrust = "unverified"
	ClientTrustConfigured ClientTrust = "configured"
)

type Client struct {
	ID            ClientID
	DisplayName   string
	Trust         ClientTrust
	RedirectURIs  []RedirectURI
	AllowedScopes ScopeSet
	CreatedAt     time.Time
	LastUsedAt    time.Time
}

type ConsentClientSnapshot struct {
	ID             ClientID
	DisplayName    string
	Trust          ClientTrust
	RedirectURI    RedirectURI
	RedirectOrigin string
}

type AuthorizationTransaction struct {
	Token           TransactionToken `json:"-"`
	ClientID        ClientID
	RedirectURI     RedirectURI
	State           string
	PKCEChallenge   PKCEChallenge
	RequestedScopes ScopeSet
	Resource        ResourceID
	ExpiresAt       time.Time
	ConsumedAt      time.Time
}

type ConsentSession[A any] struct {
	Token             ConsentToken `json:"-"`
	Client            ConsentClientSnapshot
	State             string
	PKCEChallenge     PKCEChallenge
	Principal         Principal[A] `json:"-"`
	AllowedScopes     ScopeSet
	Resource          ResourceID
	AuthorizationEnds time.Time
	ExpiresAt         time.Time
	ConsumedAt        time.Time
}

type AuthorizationCodeRecord[A any] struct {
	Digest            CredentialDigest
	ClientID          ClientID
	RedirectURI       RedirectURI
	PKCEChallenge     PKCEChallenge
	Principal         Principal[A] `json:"-"`
	Scopes            ScopeSet
	Resource          ResourceID
	State             string
	AuthorizationEnds time.Time
	ExpiresAt         time.Time
	ConsumedAt        time.Time
}

type RefreshGrant[A any] struct {
	Digest     CredentialDigest
	FamilyID   RefreshFamilyID
	Generation uint64
	ClientID   ClientID
	Principal  Principal[A] `json:"-"`
	Scopes     ScopeSet
	Resource   ResourceID
	ExpiresAt  time.Time
	ConsumedAt time.Time
	RevokedAt  time.Time
}

type LoginContext struct {
	Transaction TransactionToken
	ClientID    ClientID
	RedirectURI RedirectURI
	State       string
}

type ConsentScope struct {
	Scope       Scope
	Description string
}

type ConsentView struct {
	Token             ConsentToken
	ResourceName      string
	PrincipalName     string
	PrincipalEmail    string
	ClientName        string
	ClientTrust       ClientTrust
	RedirectOrigin    string
	RedirectURI       string
	AccessTokenTTL    time.Duration
	AuthorizationEnds time.Time
	Scopes            []ConsentScope
}

type AccessGrant[A any] struct {
	Principal Principal[A]
	ClientID  ClientID
	Resource  ResourceID
	Scopes    ScopeSet
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type IssuedAccessToken struct {
	Value     string
	TokenType string
	ExpiresAt time.Time
}

type VerifiedAccessToken struct {
	Subject     Subject
	ClientID    ClientID
	Issuer      string
	Resource    ResourceID
	Scopes      ScopeSet
	IssuedAt    time.Time
	ExpiresAt   time.Time
	TokenID     string
	ExtraClaims map[string]any
}
