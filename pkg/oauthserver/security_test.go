package oauthserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type refreshFaultStore struct {
	oauthserver.Store[struct{}]
	grant     oauthserver.RefreshGrant[struct{}]
	getErr    error
	revokeErr error
	revoked   bool
}

func (s *refreshFaultStore) GetRefreshGrant(context.Context, oauthserver.CredentialDigest) (oauthserver.RefreshGrant[struct{}], error) {
	return s.grant, s.getErr
}

func (s *refreshFaultStore) RevokeRefreshFamily(context.Context, oauthserver.RefreshFamilyID, time.Time) error {
	s.revoked = true
	return s.revokeErr
}

func newFaultEngine(t *testing.T, store oauthserver.Store[struct{}], revalidation oauthserver.Revalidation[struct{}]) *oauthserver.Engine[struct{}] {
	t.Helper()
	scopes, err := oauthserver.NewScopeSet("read")
	if err != nil {
		t.Fatal(err)
	}
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	resources, err := oauthserver.NewStaticResourceRegistry(config.Resources, config.SupportedScopes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := oauthserver.New(config, oauthserver.Dependencies[struct{}]{
		Store:       store,
		Resources:   resources,
		Scopes:      memorytest.ScopePolicy[struct{}]{Available: scopes},
		Revalidator: memorytest.Revalidator[struct{}]{Result: revalidation},
		Tokens:      &memorytest.TokenService[struct{}]{Issuer: config.Issuer},
		Secrets:     &memorytest.Secrets{},
		Clock:       memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func validRefreshGrant(t *testing.T) oauthserver.RefreshGrant[struct{}] {
	t.Helper()
	scopes, err := oauthserver.NewScopeSet("read")
	if err != nil {
		t.Fatal(err)
	}
	return oauthserver.RefreshGrant[struct{}]{
		FamilyID:  "family-000000000000000000000000000000000000",
		ClientID:  "client-1",
		Principal: oauthserver.Principal[struct{}]{Subject: "employee-1"},
		Scopes:    scopes,
		Resource:  "https://resource.example.test/api",
		ExpiresAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
	}
}

func TestRefreshPropagatesIneligibleRevocationFailure(t *testing.T) {
	failure := errors.New("database unavailable")
	store := &refreshFaultStore{grant: validRefreshGrant(t), revokeErr: failure}
	engine := newFaultEngine(t, store, oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationIneligible})

	_, err := engine.Refresh(t.Context(), oauthserver.RefreshInput{RefreshToken: "refresh-000000000000000000000000000000000000", ClientID: "client-1"})
	var oauthErr *oauthserver.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != oauthserver.ErrorTemporary || !errors.Is(err, failure) || !store.revoked {
		t.Fatalf("refresh error = %#v, revoked=%v", err, store.revoked)
	}
}

func TestRefreshRejectsOutOfRangeRevalidationStatus(t *testing.T) {
	store := &refreshFaultStore{grant: validRefreshGrant(t)}
	engine := newFaultEngine(t, store, oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationStatus(99), Principal: store.grant.Principal})

	if _, err := engine.Refresh(t.Context(), oauthserver.RefreshInput{RefreshToken: "refresh-000000000000000000000000000000000000", ClientID: "client-1"}); err == nil {
		t.Fatal("out-of-range revalidation status was accepted")
	}
}

func TestRevokeDistinguishesUnknownTokenFromStoreFailure(t *testing.T) {
	failure := errors.New("database unavailable")
	store := &refreshFaultStore{grant: validRefreshGrant(t), getErr: failure}
	engine := newFaultEngine(t, store, oauthserver.Revalidation[struct{}]{})
	if err := engine.Revoke(t.Context(), oauthserver.RevokeInput{Token: "refresh-000000000000000000000000000000000000", ClientID: "client-1"}); !errors.Is(err, failure) {
		t.Fatalf("store failure was hidden: %v", err)
	}

	store.getErr = oauthserver.ErrNotFound
	if err := engine.Revoke(t.Context(), oauthserver.RevokeInput{Token: "refresh-000000000000000000000000000000000000", ClientID: "client-1"}); err != nil {
		t.Fatalf("unknown token was disclosed: %v", err)
	}
}

func TestEngineRejectsMismatchedResourceRegistry(t *testing.T) {
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "expected", SupportedScopes: []string{"read"}}}, scopes)
	resources, err := oauthserver.NewStaticResourceRegistry([]oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "different", SupportedScopes: []string{"read"}}}, scopes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = oauthserver.New(config, oauthserver.Dependencies[struct{}]{Store: memorytest.NewStore[struct{}](), Resources: resources, Scopes: memorytest.ScopePolicy[struct{}]{Available: scopes}, Revalidator: memorytest.Revalidator[struct{}]{}, Tokens: &memorytest.TokenService[struct{}]{Issuer: config.Issuer}, Secrets: &memorytest.Secrets{}, Clock: oauthserver.SystemClock{}})
	if err == nil {
		t.Fatal("mismatched resource registry accepted")
	}
}

func TestEngineRejectsMismatchedTokenIssuer(t *testing.T) {
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	resources, err := oauthserver.NewStaticResourceRegistry(config.Resources, scopes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = oauthserver.New(config, oauthserver.Dependencies[struct{}]{Store: memorytest.NewStore[struct{}](), Resources: resources, Scopes: memorytest.ScopePolicy[struct{}]{Available: scopes}, Revalidator: memorytest.Revalidator[struct{}]{}, Tokens: &memorytest.TokenService[struct{}]{Issuer: "https://other.example.test"}, Secrets: &memorytest.Secrets{}, Clock: oauthserver.SystemClock{}})
	if err == nil {
		t.Fatal("mismatched token issuer accepted")
	}
}

func TestCompleteLoginRejectsInvalidPrincipalBeforeStateLookup(t *testing.T) {
	store := &refreshFaultStore{}
	engine := newFaultEngine(t, store, oauthserver.Revalidation[struct{}]{})
	_, err := engine.CompleteLogin(t.Context(), oauthserver.CompleteLoginInput[struct{}]{Transaction: "transaction-000000000000000000000000000000000", Principal: oauthserver.Principal[struct{}]{}})
	var oauthErr *oauthserver.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != oauthserver.ErrorAccessDenied {
		t.Fatalf("invalid principal error = %#v", err)
	}
}
