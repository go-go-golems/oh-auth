package httptransport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/httptransport"
	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type loginStarter struct{}

func (loginStarter) AuthorizationURL(_ context.Context, login oauthserver.LoginContext) (string, error) {
	return "/login?transaction=" + string(login.Transaction), nil
}

func newServer(t *testing.T) (*httptransport.Server[struct{}], *memorytest.Store[struct{}]) {
	t.Helper()
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://mcp.example.test/mcp", DisplayName: "MCP", SupportedScopes: []string{"read"}}}, scopes)
	store := memorytest.NewStore[struct{}]()
	clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	resources, err := oauthserver.NewStaticResourceRegistry(config.Resources, config.SupportedScopes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := oauthserver.New(config, oauthserver.Dependencies[struct{}]{Store: store, Resources: resources, Scopes: memorytest.ScopePolicy[struct{}]{Available: scopes}, Revalidator: memorytest.Revalidator[struct{}]{Result: oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationEligible, Principal: oauthserver.Principal[struct{}]{Subject: "employee-1", DisplayName: "Employee", Email: "employee@example.test"}}}, Tokens: &memorytest.TokenService[struct{}]{}, Secrets: &memorytest.Secrets{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	server, err := httptransport.New(httptransport.Config[struct{}]{Engine: engine, Issuer: config.Issuer, Resources: resources, Tokens: &memorytest.TokenService[struct{}]{}, Login: loginStarter{}, Policy: config.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return server, store
}

func TestServerMetadataRegistrationAndBoundaries(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)

	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/.well-known/oauth-authorization-server", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("metadata response: %d %v", response.Code, response.Header())
	}
	var metadata map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["issuer"] != "https://auth.example.test" {
		t.Fatalf("metadata: %+v", metadata)
	}

	bad := httptest.NewRequest(http.MethodPost, "https://auth.example.test/.well-known/oauth-authorization-server", nil)
	badResponse := httptest.NewRecorder()
	mux.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusMethodNotAllowed || badResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST metadata: %d %v", badResponse.Code, badResponse.Header())
	}

	body := strings.NewReader(`{"displayName":"test","redirectURIs":["https://client.example.test/callback"],"requestedScopes":["read"]}`)
	register := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", body)
	register.Header.Set("Content-Type", "application/json")
	registerResponse := httptest.NewRecorder()
	mux.ServeHTTP(registerResponse, register)
	if registerResponse.Code != http.StatusCreated {
		t.Fatalf("registration status = %d body=%s", registerResponse.Code, registerResponse.Body.String())
	}

	unsupported := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", strings.NewReader(`{}`))
	unsupported.Header.Set("Content-Type", "text/plain")
	unsupportedResponse := httptest.NewRecorder()
	mux.ServeHTTP(unsupportedResponse, unsupported)
	if unsupportedResponse.Code != http.StatusBadRequest {
		t.Fatalf("unsupported content type status = %d", unsupportedResponse.Code)
	}
}
