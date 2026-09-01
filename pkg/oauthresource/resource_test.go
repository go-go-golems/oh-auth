package oauthresource_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-go-golems/oh-auth/pkg/oauthresource"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type verifier struct {
	raw      string
	resource oauthserver.ResourceID
}

func (v *verifier) VerifyAccessToken(_ context.Context, raw string, resource oauthserver.ResourceID) (oauthserver.VerifiedAccessToken, error) {
	v.raw, v.resource = raw, resource
	return oauthserver.VerifiedAccessToken{Subject: "subject-1", Resource: resource}, nil
}

func TestAuthenticateExtractsBearerAndBindsResource(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://resource.example.test/api", nil)
	request.Header.Set("Authorization", "Bearer token-value")
	v := &verifier{}
	verified, err := oauthresource.Authenticate(t.Context(), v, "https://resource.example.test/api", request)
	if err != nil {
		t.Fatal(err)
	}
	if v.raw != "token-value" || v.resource != verified.Resource {
		t.Fatalf("verification binding raw=%q resource=%q verified=%q", v.raw, v.resource, verified.Resource)
	}
}

func TestBearerTokenRejectsAmbiguousAuthorization(t *testing.T) {
	for _, value := range []string{"", "Basic value", "Bearer", "Bearer one two", "Bearer one\r\ntwo"} {
		request := httptest.NewRequest(http.MethodGet, "https://resource.example.test/api", nil)
		request.Header["Authorization"] = []string{value}
		if _, err := oauthresource.BearerToken(request); err == nil {
			t.Fatalf("accepted Authorization %q", value)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "https://resource.example.test/api", nil)
	request.Header["Authorization"] = []string{"Bearer one", "Bearer two"}
	if _, err := oauthresource.BearerToken(request); err == nil {
		t.Fatal("accepted multiple Authorization headers")
	}
}

func TestMetadataAndChallenge(t *testing.T) {
	metadata := oauthresource.Metadata{Resource: "https://resource.example.test/api", AuthorizationServers: []string{"https://auth.example.test"}, ScopesSupported: []string{"read"}, ResourceName: "resource"}
	response := httptest.NewRecorder()
	metadata.Handler(response, httptest.NewRequest(http.MethodGet, "https://resource.example.test/.well-known/oauth-protected-resource", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"resource":"https://resource.example.test/api"`) {
		t.Fatalf("metadata = %d %s", response.Code, response.Body.String())
	}
	if challenge := oauthresource.BearerChallenge("https://resource.example.test/.well-known/oauth-protected-resource"); challenge != `Bearer error="invalid_token", resource_metadata="https://resource.example.test/.well-known/oauth-protected-resource"` {
		t.Fatalf("challenge = %q", challenge)
	}
}
