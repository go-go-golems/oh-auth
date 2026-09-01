package httptransport_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type callbackAuthenticator struct{}

func (callbackAuthenticator) AuthenticateCallback(_ context.Context, r *http.Request) (oauthserver.TransactionToken, oauthserver.Principal[struct{}], error) {
	transaction, err := oauthserver.NewTransactionToken(r.URL.Query().Get("transaction"))
	return transaction, oauthserver.Principal[struct{}]{Subject: "employee-1", DisplayName: "Employee", Email: "employee@example.test"}, err
}

func TestHTTPAuthorizationCodeRefreshAndRevokeFlow(t *testing.T) {
	server, _ := newServer(t)
	mux := http.NewServeMux()
	server.Mount(mux)
	mux.Handle("/callback", server.IdentityCallbackHandler(callbackAuthenticator{}))

	registration := postJSON(t, mux, "/oauth/register", `{"client_name":"flow","redirect_uris":["https://client.example.test/callback"],"scope":"read"}`)
	var registered map[string]any
	decodeResponse(t, registration, &registered)
	clientID := registered["client_id"].(string)

	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	authorizeValues := url.Values{"client_id": {clientID}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "state": {"state-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"read"}, "resource": {"https://mcp.example.test/mcp"}}
	authorize := request(t, mux, http.MethodGet, "/oauth/authorize?"+authorizeValues.Encode(), "", "")
	loginURL := parseLocation(t, authorize)
	transaction := loginURL.Query().Get("transaction")
	if transaction == "" {
		t.Fatalf("missing login transaction: %s", loginURL)
	}

	callback := request(t, mux, http.MethodGet, "/callback?transaction="+url.QueryEscape(transaction), "", "")
	consentURL := parseLocation(t, callback)
	consentPage := request(t, mux, http.MethodGet, consentURL.RequestURI(), "", "")
	if consentPage.Code != http.StatusOK || !strings.Contains(consentPage.Body.String(), "Authorize flow") {
		t.Fatalf("consent page = %d %s", consentPage.Code, consentPage.Body.String())
	}

	consentValues := url.Values{"token": {consentURL.Query().Get("token")}, "decision": {"approve"}, "scope": {"read"}}
	consent := request(t, mux, http.MethodPost, "/oauth/consent", consentValues.Encode(), "application/x-www-form-urlencoded")
	clientCallback := parseLocation(t, consent)
	code := clientCallback.Query().Get("code")
	if code == "" || clientCallback.Query().Get("state") != "state-1" {
		t.Fatalf("authorization callback = %s", clientCallback)
	}

	tokenValues := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {"https://client.example.test/callback"}, "code_verifier": {verifier}}
	tokenResponse := request(t, mux, http.MethodPost, "/oauth/token", tokenValues.Encode(), "application/x-www-form-urlencoded")
	var tokens map[string]any
	decodeResponse(t, tokenResponse, &tokens)
	if tokens["access_token"] == "" || tokens["refresh_token"] == "" {
		t.Fatalf("token response = %#v", tokens)
	}

	refreshValues := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID}}
	refreshResponse := request(t, mux, http.MethodPost, "/oauth/token", refreshValues.Encode(), "application/x-www-form-urlencoded")
	var refreshed map[string]any
	decodeResponse(t, refreshResponse, &refreshed)
	if refreshed["refresh_token"] == tokens["refresh_token"] {
		t.Fatal("refresh token did not rotate")
	}

	revokeValues := url.Values{"token": {refreshed["refresh_token"].(string)}, "client_id": {clientID}}
	revoke := request(t, mux, http.MethodPost, "/oauth/revoke", revokeValues.Encode(), "application/x-www-form-urlencoded")
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", revoke.Code, revoke.Body.String())
	}
	refreshValues.Set("refresh_token", refreshed["refresh_token"].(string))
	revokedRefresh := request(t, mux, http.MethodPost, "/oauth/token", refreshValues.Encode(), "application/x-www-form-urlencoded")
	if revokedRefresh.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh = %d %s", revokedRefresh.Code, revokedRefresh.Body.String())
	}
}

func request(t *testing.T, handler http.Handler, method, target, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "https://auth.example.test"+target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func postJSON(t *testing.T, handler http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	return request(t, handler, http.MethodPost, target, body, "application/json")
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if response.Code < 200 || response.Code >= 300 {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatal(err)
	}
}

func parseLocation(t *testing.T, response *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if response.Code != http.StatusFound {
		t.Fatalf("redirect = %d %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return location
}
