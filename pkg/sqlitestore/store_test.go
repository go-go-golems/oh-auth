package sqlitestore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

func TestStoreTransitionsAndDigestOnlyState(t *testing.T) {
	ctx := context.Background()
	store, err := sqlitestore.Open[struct{}](ctx, filepath.Join(t.TempDir(), "oauth.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	scopes, _ := oauthserver.NewScopeSet("read")
	client := oauthserver.Client{ID: "client-1", DisplayName: "client", Trust: oauthserver.ClientTrustUnverified, RedirectURIs: []oauthserver.RedirectURI{"https://client.example.test/callback"}, AllowedScopes: scopes, CreatedAt: now, LastUsedAt: now}
	policy := oauthserver.StatePolicy{Registration: oauthserver.RegistrationPolicy{MaxClients: 4}, Capacity: oauthserver.StateCapacity{MaxAuthorizations: 4, MaxConsents: 4, MaxCodes: 4, MaxRefreshGrants: 4}, Retention: oauthserver.RetentionPolicy{ConsumedState: time.Hour}}
	if err := store.RegisterClient(ctx, client, policy); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetClient(ctx, client.ID); err != nil || got.ID != client.ID {
		t.Fatalf("get client: %+v %v", got, err)
	}
	txToken, _ := oauthserver.NewTransactionToken("transaction-000000000000000000000000000000000000")
	resource, _ := oauthserver.NewResourceID("https://mcp.example.test/mcp")
	challenge, _ := oauthserver.NewPKCEChallenge("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "S256")
	state := oauthserver.AuthorizationTransaction{Token: txToken, ClientID: client.ID, RedirectURI: client.RedirectURIs[0], State: "state", PKCEChallenge: challenge, RequestedScopes: scopes, Resource: resource, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateAuthorization(ctx, state, policy); err != nil {
		t.Fatal(err)
	}
	consentToken, _ := oauthserver.NewConsentToken("consent-000000000000000000000000000000000000")
	principal := oauthserver.Principal[struct{}]{Subject: "employee-1", DisplayName: "Employee"}
	consent := oauthserver.ConsentSession[struct{}]{Token: consentToken, Client: oauthserver.ConsentClientSnapshot{ID: client.ID, DisplayName: client.DisplayName, Trust: client.Trust, RedirectURI: client.RedirectURIs[0]}, State: state.State, PKCEChallenge: challenge, Principal: principal, AllowedScopes: scopes, Resource: resource, ExpiresAt: now.Add(10 * time.Minute)}
	if err := store.CommitLogin(ctx, oauthserver.LoginCommit[struct{}]{TransactionDigest: oauthserver.DigestCredential(string(txToken)), Consent: consent}, policy); err != nil {
		t.Fatal(err)
	}
	gotConsent, err := store.GetConsent(ctx, oauthserver.DigestCredential(string(consentToken)))
	if err != nil || gotConsent.Principal.Subject != principal.Subject {
		t.Fatalf("get consent: %+v %v", gotConsent, err)
	}
	codeToken, _ := oauthserver.NewAuthorizationCode("code-000000000000000000000000000000000000")
	code := oauthserver.AuthorizationCodeRecord[struct{}]{Digest: oauthserver.DigestCredential(string(codeToken)), ClientID: client.ID, RedirectURI: client.RedirectURIs[0], PKCEChallenge: challenge, Principal: principal, Scopes: scopes, Resource: resource, ExpiresAt: now.Add(time.Minute)}
	if _, err := store.CommitConsent(ctx, oauthserver.ConsentCommit[struct{}]{ConsentDigest: oauthserver.DigestCredential(string(consentToken)), Code: code, Decision: oauthserver.ConsentDecisionApprove}, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConsent(ctx, oauthserver.ConsentCommit[struct{}]{ConsentDigest: oauthserver.DigestCredential(string(consentToken)), Code: code, Decision: oauthserver.ConsentDecisionApprove}, policy); err == nil {
		t.Fatal("consent replay accepted")
	}
	if _, err := store.GetCodeForExchange(ctx, oauthserver.CodeExchangeBinding{Digest: code.Digest, ClientID: client.ID, RedirectURI: client.RedirectURIs[0]}); err != nil {
		t.Fatal(err)
	}
	refreshToken, _ := oauthserver.NewRefreshToken("refresh-000000000000000000000000000000000000")
	family, _ := oauthserver.NewRefreshFamilyID("family-000000000000000000000000000000000000")
	grant := oauthserver.RefreshGrant[struct{}]{Digest: oauthserver.DigestCredential(string(refreshToken)), FamilyID: family, ClientID: client.ID, Principal: principal, Scopes: scopes, Resource: resource, ExpiresAt: now.Add(24 * time.Hour)}
	if err := store.CommitCodeExchange(ctx, oauthserver.CodeExchangeCommit[struct{}]{CodeDigest: code.Digest, Refresh: &grant}, policy); err != nil {
		t.Fatal(err)
	}
	nextToken, _ := oauthserver.NewRefreshToken("refresh-next-000000000000000000000000000000")
	next := grant
	next.Digest = oauthserver.DigestCredential(string(nextToken))
	next.Generation = 1
	if err := store.CommitRefreshRotation(ctx, oauthserver.RefreshRotation[struct{}]{CurrentDigest: grant.Digest, FamilyID: family, Generation: 0, Successor: next}, policy); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitRefreshRotation(ctx, oauthserver.RefreshRotation[struct{}]{CurrentDigest: grant.Digest, FamilyID: family, Generation: 0, Successor: next}, policy); err == nil {
		t.Fatal("refresh replay accepted")
	}
	rotated, err := store.GetRefreshGrant(ctx, next.Digest)
	if err != nil || rotated.RevokedAt.IsZero() {
		t.Fatalf("family was not revoked: %+v %v", rotated, err)
	}
}
