package oauthserver

import (
	"net/url"
	"strings"
	"time"
)

type ResourceConfig struct {
	ID              string
	DisplayName     string
	SupportedScopes []string
}

type Config struct {
	Issuer          string
	Resources       []ResourceConfig
	SupportedScopes ScopeSet
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	TransactionTTL  time.Duration
	ConsentTTL      time.Duration
	CodeTTL         time.Duration
	StatePolicy     StatePolicy
	HTTP            HTTPPolicy
}

type StatePolicy struct {
	Registration RegistrationPolicy
	Capacity     StateCapacity
	Retention    RetentionPolicy
}

type RegistrationPolicy struct {
	MaxClients       int
	MaxRedirectURIs  int
	MaxDisplayName   int
	MaxScopeCount    int
	MaxRedirectBytes int
}

type StateCapacity struct {
	MaxAuthorizations int
	MaxConsents       int
	MaxCodes          int
	MaxRefreshGrants  int
}

type RetentionPolicy struct {
	ConsumedState time.Duration
	RevokedState  time.Duration
}

type HTTPPolicy struct {
	MaxBodyBytes   int64
	MaxFieldBytes  int
	MaxArrayLength int
}

func DefaultConfig(issuer string, resources []ResourceConfig, scopes ScopeSet) Config {
	return Config{
		Issuer:          issuer,
		Resources:       resources,
		SupportedScopes: scopes,
		AccessTTL:       10 * time.Minute,
		RefreshTTL:      30 * 24 * time.Hour,
		TransactionTTL:  5 * time.Minute,
		ConsentTTL:      10 * time.Minute,
		CodeTTL:         time.Minute,
		StatePolicy: StatePolicy{
			Registration: RegistrationPolicy{MaxClients: 256, MaxRedirectURIs: 16, MaxDisplayName: 128, MaxScopeCount: 64, MaxRedirectBytes: 2048},
			Capacity:     StateCapacity{MaxAuthorizations: 1024, MaxConsents: 1024, MaxCodes: 1024, MaxRefreshGrants: 4096},
			Retention:    RetentionPolicy{ConsumedState: time.Hour, RevokedState: 24 * time.Hour},
		},
		HTTP: HTTPPolicy{MaxBodyBytes: 1 << 20, MaxFieldBytes: 4096, MaxArrayLength: 64},
	}
}

func (c Config) Validate() error {
	if !validOrigin(c.Issuer, false) {
		return invalidValue("issuer")
	}
	if len(c.Resources) == 0 || c.AccessTTL <= 0 || c.RefreshTTL <= 0 || c.TransactionTTL <= 0 || c.ConsentTTL <= 0 || c.CodeTTL <= 0 {
		return invalidValue("configuration")
	}
	seen := make(map[ResourceID]struct{}, len(c.Resources))
	for _, rc := range c.Resources {
		id, err := NewResourceID(rc.ID)
		if err != nil || !validOrigin(string(id), true) || strings.TrimSpace(rc.DisplayName) == "" {
			return invalidValue("resource configuration")
		}
		if _, exists := seen[id]; exists {
			return invalidValue("duplicate resource")
		}
		seen[id] = struct{}{}
		resourceScopes, err := NewScopeSet(stringsToScopes(rc.SupportedScopes)...)
		if err != nil || !resourceScopes.IsSubsetOf(c.SupportedScopes) {
			return invalidValue("resource scopes")
		}
	}
	if c.StatePolicy.Registration.MaxClients <= 0 || c.StatePolicy.Capacity.MaxCodes <= 0 || c.HTTP.MaxBodyBytes <= 0 {
		return invalidValue("state policy")
	}
	return nil
}

func validOrigin(raw string, allowLoopback bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return allowLoopback && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "[::1]")
}

func stringsToScopes(values []string) []Scope {
	result := make([]Scope, len(values))
	for i, value := range values {
		result[i] = Scope(value)
	}
	return result
}
