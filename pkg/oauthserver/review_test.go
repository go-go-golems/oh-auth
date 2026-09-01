package oauthserver_test

import (
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

func TestConfigRejectsUnusableOperationalLimits(t *testing.T) {
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	config.StatePolicy.Capacity.MaxRefreshGrants = 0
	if err := config.Validate(); err == nil {
		t.Fatal("zero refresh capacity accepted")
	}
	config = oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	config.StatePolicy.Registration.MaxRedirectURIs = 0
	if err := config.Validate(); err == nil {
		t.Fatal("zero redirect capacity accepted")
	}
}

func TestConfigRejectsIssuerPath(t *testing.T) {
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test/base", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	if err := config.Validate(); err == nil {
		t.Fatal("issuer path accepted without route-prefix support")
	}
}

func TestRedirectURIQueryAndIPv6LoopbackAreSupported(t *testing.T) {
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	resources, err := oauthserver.NewStaticResourceRegistry(config.Resources, config.SupportedScopes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := oauthserver.New(config, oauthserver.Dependencies[struct{}]{Store: memorytest.NewStore[struct{}](), Resources: resources, Scopes: memorytest.ScopePolicy[struct{}]{Available: scopes}, Revalidator: memorytest.Revalidator[struct{}]{Result: oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationEligible, Principal: oauthserver.Principal[struct{}]{Subject: "employee-1"}}}, Tokens: &memorytest.TokenService[struct{}]{}, Secrets: &memorytest.Secrets{}, Clock: memorytest.NewClock(time.Now().UTC())})
	if err != nil {
		t.Fatal(err)
	}
	for _, redirect := range []string{"https://client.example.test/callback?tenant=a", "http://[::1]:8080/callback"} {
		if _, err := engine.RegisterClient(t.Context(), oauthserver.RegisterClientInput{DisplayName: "client", RedirectURIs: []string{redirect}, RequestedScopes: []string{"read"}}); err != nil {
			t.Fatalf("register %q: %v", redirect, err)
		}
	}
}
