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

func TestVerificationOnlyResourceServer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	issuer := "https://auth.example.test"
	service, err := jwttokens.New(jwttokens.Config[struct{}]{Issuer: issuer, ActiveKeyID: "active", ActiveKey: key, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := oauthserver.NewScopeSet("rag:documents:read")
	issued, err := service.IssueAccessToken(context.Background(), oauthserver.AccessGrant[struct{}]{Principal: oauthserver.Principal[struct{}]{Subject: "employee-1"}, ClientID: "client-1", Resource: "https://rag.example.test/api", Scopes: scopes, IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jwttokens.NewVerifier(jwttokens.VerificationConfig{Issuer: issuer, Keys: map[string]*rsa.PublicKey{"active": &key.PublicKey}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyAccessToken(context.Background(), issued.Value, "https://rag.example.test/api")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Subject != "employee-1" || verified.Scopes.String() != "rag:documents:read" {
		t.Fatalf("unexpected verified token: %+v", verified)
	}
	if _, err := verifier.VerifyAccessToken(context.Background(), issued.Value, "https://mcp.example.test/mcp"); err == nil {
		t.Fatal("verification-only resource server accepted the wrong audience")
	}
}

func TestVerifierRejectsIncompleteTrustConfiguration(t *testing.T) {
	if _, err := jwttokens.NewVerifier(jwttokens.VerificationConfig{Issuer: "https://auth.example.test"}); err == nil {
		t.Fatal("verifier without keys succeeded")
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwttokens.NewVerifier(jwttokens.VerificationConfig{Issuer: "https://auth.example.test", Keys: map[string]*rsa.PublicKey{"weak": &weak.PublicKey}}); err == nil {
		t.Fatal("verifier accepted a weak key")
	}
}

func TestServiceRejectsWeakRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwttokens.New(jwttokens.Config[struct{}]{Issuer: "https://auth.example.test", ActiveKeyID: "weak", ActiveKey: key}); err == nil {
		t.Fatal("weak RSA key accepted")
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
