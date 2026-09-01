package oauthserver_test

import (
	"testing"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

func FuzzOAuthValueParsers(f *testing.F) {
	for _, seed := range []string{"https://client.example.test/callback", "http://[::1]:8080/callback", "read", "", "%%%", "https://user@example.test/callback#fragment"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = oauthserver.NewRedirectURI(raw)
		_, _ = oauthserver.NewResourceID(raw)
		_, _ = oauthserver.NewScope(raw)
		_, _ = oauthserver.ParseScopes(raw)
		_ = oauthserver.ValidatePKCEVerifier(raw)
	})
}
