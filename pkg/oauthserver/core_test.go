package oauthserver_test

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

func TestScopeSetCanonicalAndImmutable(t *testing.T) {
	set, err := oauthserver.NewScopeSet("read", "write", "read")
	if err != nil {
		t.Fatal(err)
	}
	values := set.Values()
	values[0] = "mutated"
	if got := set.String(); got != "read write" {
		t.Fatalf("String() = %q", got)
	}
	other, _ := oauthserver.NewScopeSet("read", "admin")
	if got := set.Intersect(other).String(); got != "read" {
		t.Fatalf("intersection = %q", got)
	}
	if !set.Intersect(other).IsSubsetOf(set) {
		t.Fatal("intersection must be a subset")
	}
}

func TestPKCES256(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	digest := oauthserver.DigestCredential(verifier)
	challengeValue := base64.RawURLEncoding.EncodeToString(digest[:])
	challenge, err := oauthserver.NewPKCEChallenge(challengeValue, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if err := challenge.Verify(verifier); err != nil {
		t.Fatal(err)
	}
	if err := challenge.Verify(strings.Repeat("b", 43)); err == nil {
		t.Fatal("wrong verifier accepted")
	}
}

func TestEngineOAuthLifecycle(t *testing.T) {
	ctx := context.Background()
	scopes, _ := oauthserver.NewScopeSet("documents:read", "documents:write")
	resourceID := "https://rag.example.test/api"
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: resourceID, DisplayName: "RAG", SupportedScopes: []string{"documents:read", "documents:write"}}}, scopes)
	clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	store := memorytest.NewStoreWithClock[struct{}](clock)
	secrets := &memorytest.Secrets{}
	resources, err := oauthserver.NewStaticResourceRegistry(config.Resources, config.SupportedScopes)
	if err != nil {
		t.Fatal(err)
	}
	principal := oauthserver.Principal[struct{}]{Subject: oauthserver.Subject("employee-1"), DisplayName: "Employee", Email: "employee@example.test"}
	revalidator := &memorytest.Revalidator[struct{}]{Result: oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationEligible, Principal: principal}}
	engine, err := oauthserver.New(config, oauthserver.Dependencies[struct{}]{Store: store, Resources: resources, Scopes: memorytest.ScopePolicy[struct{}]{Available: scopes}, Revalidator: revalidator, Tokens: &memorytest.TokenService[struct{}]{Issuer: config.Issuer}, Secrets: secrets, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := engine.RegisterClient(ctx, oauthserver.RegisterClientInput{DisplayName: "Test client", RedirectURIs: []string{"https://client.example.test/callback"}, RequestedScopes: []string{"documents:read"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	digest := oauthserver.DigestCredential(verifier)
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	started, err := engine.BeginAuthorization(ctx, oauthserver.BeginAuthorizationInput{ClientID: string(registered.Client.ID), RedirectURI: string(registered.Client.RedirectURIs[0]), ResponseType: "code", State: "state-1", CodeChallenge: challenge, ChallengeMethod: "S256", Scopes: []string{"documents:read"}, Resource: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := engine.CompleteLogin(ctx, oauthserver.CompleteLoginInput[struct{}]{Transaction: started.Transaction, Principal: principal})
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.ConsentView(ctx, completed.ConsentToken)
	if err != nil {
		t.Fatal(err)
	}
	if view.ResourceName != "RAG" || len(view.Scopes) != 1 || view.RedirectURI == "" {
		t.Fatalf("unexpected consent view: %+v", view)
	}
	decided, err := engine.DecideConsent(ctx, oauthserver.DecideConsentInput{Token: completed.ConsentToken, Decision: oauthserver.ConsentDecisionApprove, SelectedScopes: []oauthserver.Scope{"documents:read"}})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(decided.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("code")
	if code == "" || redirect.Query().Get("state") != "state-1" {
		t.Fatalf("unexpected redirect %s", decided.RedirectURI)
	}
	if _, err := engine.ExchangeCode(ctx, oauthserver.ExchangeCodeInput{Code: code, ClientID: string(registered.Client.ID), RedirectURI: string(registered.Client.RedirectURIs[0]), CodeVerifier: strings.Repeat("x", 43)}); err == nil {
		t.Fatal("wrong verifier accepted")
	}
	tokens, err := engine.ExchangeCode(ctx, oauthserver.ExchangeCodeInput{Code: code, ClientID: string(registered.Client.ID), RedirectURI: string(registered.Client.RedirectURIs[0]), CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.Scopes.String() != "documents:read" {
		t.Fatalf("unexpected token response: %+v", tokens)
	}
	revalidator.Result = oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationEligible, Principal: oauthserver.Principal[struct{}]{Subject: "other-employee"}}
	if _, err := engine.Refresh(ctx, oauthserver.RefreshInput{RefreshToken: tokens.RefreshToken, ClientID: string(registered.Client.ID)}); err == nil {
		t.Fatal("refresh accepted revalidation for another subject")
	}
	revalidator.Result = oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationEligible, Principal: principal}
	refreshed, err := engine.Refresh(ctx, oauthserver.RefreshInput{RefreshToken: tokens.RefreshToken, ClientID: string(registered.Client.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken == tokens.RefreshToken || refreshed.Scopes.String() != "documents:read" {
		t.Fatalf("refresh did not rotate: %+v", refreshed)
	}
	if err := engine.Revoke(ctx, oauthserver.RevokeInput{Token: refreshed.RefreshToken, ClientID: string(registered.Client.ID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Refresh(ctx, oauthserver.RefreshInput{RefreshToken: refreshed.RefreshToken, ClientID: string(registered.Client.ID)}); err == nil {
		t.Fatal("revoked grant refreshed")
	}
}
