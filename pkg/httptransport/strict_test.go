package httptransport_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFormMediaTypeParametersAreAccepted(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/revoke", strings.NewReader("token=unknown-token-000000000000000000&client_id=client-1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("parameterized form media type status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestTokenEndpointRejectsDuplicateAndQueryParameters(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)
	for name, testCase := range map[string]struct {
		target string
		body   string
	}{
		"duplicate scalar": {"https://auth.example.test/oauth/token", "grant_type=refresh_token&grant_type=authorization_code"},
		"query parameter":  {"https://auth.example.test/oauth/token?client_id=query-client", "grant_type=refresh_token&client_id=body-client"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, testCase.target, strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAuthorizationRejectsDuplicateBindings(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/oauth/authorize?client_id=one&client_id=two", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate authorization binding status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestLoginStartupFailureReturnsToTrustedClient(t *testing.T) {
	server, _ := newServerWithLogin(t, nil)
	mux := http.NewServeMux()
	server.Mount(mux)
	register := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", strings.NewReader(`{"client_name":"test","redirect_uris":["https://client.example.test/callback"],"scope":"read"}`))
	register.Header.Set("Content-Type", "application/json")
	registrationResponse := httptest.NewRecorder()
	mux.ServeHTTP(registrationResponse, register)
	var registration map[string]any
	if err := json.Unmarshal(registrationResponse.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	values := url.Values{"client_id": {registration["client_id"].(string)}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "state": {"state-1"}, "code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"}, "scope": {"read"}, "resource": {"https://mcp.example.test/mcp"}}
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/oauth/authorize?"+values.Encode(), nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusFound || location.Query().Get("error") != "temporarily_unavailable" || location.Query().Get("state") != "state-1" {
		t.Fatalf("login startup error response = %d %s", response.Code, location)
	}
}

func TestRegistrationRejectsUnsupportedOrDuplicateMetadata(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)
	for name, body := range map[string]string{
		"unsupported grant":  `{"client_name":"test","redirect_uris":["https://client.example.test/callback"],"scope":"read","grant_types":["client_credentials"]}`,
		"duplicate response": `{"client_name":"test","redirect_uris":["https://client.example.test/callback"],"scope":"read","response_types":["code","code"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/oauth/register", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
