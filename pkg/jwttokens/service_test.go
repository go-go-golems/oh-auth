package jwttokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/jwttokens"
	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type claims struct{}

func (claims) ExtraClaims(context.Context, oauthserver.Principal[struct{}]) (map[string]any, error) {
	return map[string]any{"employee": "e-1"}, nil
}

type reservedClaims struct{}

func (reservedClaims) ExtraClaims(context.Context, oauthserver.Principal[struct{}]) (map[string]any, error) {
	return map[string]any{"aud": "attacker"}, nil
}

func TestServiceIssuesAndVerifiesResourceBoundToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	service, err := jwttokens.New(jwttokens.Config[struct{}]{Issuer: "https://auth.example.test", ActiveKeyID: "active", ActiveKey: key, Verification: map[string]*rsa.PublicKey{"active": &key.PublicKey}, Claims: claims{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := oauthserver.NewScopeSet("read")
	principal := oauthserver.Principal[struct{}]{Subject: "employee-1"}
	token, err := service.IssueAccessToken(context.Background(), oauthserver.AccessGrant[struct{}]{Principal: principal, ClientID: "client-1", Resource: "https://mcp.example.test/mcp", Scopes: scopes, IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyAccessToken(context.Background(), token.Value, "https://mcp.example.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Subject != principal.Subject || verified.Resource != "https://mcp.example.test/mcp" || verified.Scopes.String() != "read" || verified.ExtraClaims["employee"] != "e-1" {
		t.Fatalf("unexpected verified token: %+v", verified)
	}
	if _, err := service.VerifyAccessToken(context.Background(), token.Value, "https://rag.example.test/api"); err == nil {
		t.Fatal("token crossed resource boundary")
	}
	keys, err := service.JWKS(context.Background())
	if err != nil || len(keys.Keys) != 1 {
		t.Fatalf("unexpected JWKS: %+v, %v", keys, err)
	}
}

func TestServiceRejectsReservedClaimProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	service, err := jwttokens.New(jwttokens.Config[struct{}]{Issuer: "https://auth.example.test", ActiveKeyID: "active", ActiveKey: key, Verification: map[string]*rsa.PublicKey{"active": &key.PublicKey}, Claims: reservedClaims{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.IssueAccessToken(context.Background(), oauthserver.AccessGrant[struct{}]{Principal: oauthserver.Principal[struct{}]{Subject: "employee-1"}, ClientID: "client-1", Resource: "https://mcp.example.test/mcp", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil {
		t.Fatal("reserved claim provider accepted")
	}
}
