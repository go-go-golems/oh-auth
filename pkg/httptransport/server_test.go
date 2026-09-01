package httptransport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func newServer(t *testing.T, policies ...oauthserver.HTTPPolicy) (*httptransport.Server[struct{}], *memorytest.Store[struct{}]) {
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
	policy := config.HTTP
	if len(policies) > 0 {
		policy = policies[0]
	}
	server, err := httptransport.New(httptransport.Config[struct{}]{Engine: engine, Issuer: config.Issuer, Resources: resources, Tokens: &memorytest.TokenService[struct{}]{}, Login: loginStarter{}, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	return server, store
}

func TestServerMetadataRegistrationAndBoundaries(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)

	request := httptest.NewRequest(http.MethodGet, "https://internal.invalid/.well-known/oauth-authorization-server", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("metadata response: %d %v", response.Code, response.Header())
	}
	var metadata map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["issuer"] != "https://auth.example.test" || metadata["authorization_endpoint"] != "https://auth.example.test/oauth/authorize" {
		t.Fatalf("metadata: %+v", metadata)
	}

	bad := httptest.NewRequest(http.MethodPost, "https://auth.example.test/.well-known/oauth-authorization-server", nil)
	badResponse := httptest.NewRecorder()
	mux.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusMethodNotAllowed || badResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST metadata: %d %v", badResponse.Code, badResponse.Header())
	}

	body := strings.NewReader(`{"client_name":"test","redirect_uris":["https://client.example.test/callback"],"scope":"read"}`)
	register := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", body)
	register.Header.Set("Content-Type", "application/json")
	registerResponse := httptest.NewRecorder()
	mux.ServeHTTP(registerResponse, register)
	if registerResponse.Code != http.StatusCreated {
		t.Fatalf("registration status = %d body=%s", registerResponse.Code, registerResponse.Body.String())
	}
	var registration map[string]any
	if err := json.Unmarshal(registerResponse.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	if registration["client_id"] == nil || registration["client_name"] != "test" {
		t.Fatalf("non-RFC registration response: %+v", registration)
	}
	if location := registerResponse.Header().Get("Location"); location != "" {
		t.Fatalf("registration advertised unsupported management resource %q", location)
	}

	unsupported := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", strings.NewReader(`{}`))
	unsupported.Header.Set("Content-Type", "text/plain")
	unsupportedResponse := httptest.NewRecorder()
	mux.ServeHTTP(unsupportedResponse, unsupported)
	if unsupportedResponse.Code != http.StatusBadRequest {
		t.Fatalf("unsupported content type status = %d", unsupportedResponse.Code)
	}
}

func TestTrustedAuthorizationErrorsReturnToClient(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)
	register := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", strings.NewReader(`{"client_name":"test","redirect_uris":["https://client.example.test/callback"],"scope":"read"}`))
	register.Header.Set("Content-Type", "application/json")
	registeredResponse := httptest.NewRecorder()
	mux.ServeHTTP(registeredResponse, register)
	var registered map[string]any
	if err := json.Unmarshal(registeredResponse.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	values := url.Values{"client_id": {registered["client_id"].(string)}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "state": {"state-1"}, "code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"}, "scope": {"read"}, "resource": {"https://unknown.example.test/api"}}
	request := httptest.NewRequest(http.MethodGet, "https://internal.invalid/oauth/authorize?"+values.Encode(), nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("authorization error status = %d body=%s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != "client.example.test" || location.Query().Get("state") != "state-1" || location.Query().Get("error") != "invalid_target" {
		t.Fatalf("unexpected error redirect: %s", location)
	}
}

func TestFormBodyLimitAppliesBeforeParsing(t *testing.T) {
	server, _ := newServer(t, oauthserver.HTTPPolicy{MaxBodyBytes: 32, MaxFieldBytes: 16, MaxArrayLength: 2})
	mux := http.NewServeMux()
	server.Mount(mux)
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/token", strings.NewReader("grant_type=refresh_token&client_id=client-1&refresh_token=too-large-for-policy"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized form status = %d", response.Code)
	}
}
