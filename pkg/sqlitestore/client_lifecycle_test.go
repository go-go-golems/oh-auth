package sqlitestore_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

func TestUnverifiedClientCapacityRecoversAfterIdleTTL(t *testing.T) {
	ctx := context.Background()
	store, err := sqlitestore.Open[struct{}](ctx, filepath.Join(t.TempDir(), "oauth.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	policy := lifecyclePolicy(t)
	old := lifecycleClient(t, "client-old", time.Now().UTC().Add(-2*time.Hour))
	if err := store.RegisterClient(ctx, old, policy); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterClient(ctx, lifecycleClient(t, "client-new", time.Now().UTC()), policy); err != nil {
		t.Fatalf("idle client did not release capacity: %v", err)
	}
	if _, err := store.GetClient(ctx, old.ID); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatalf("idle client still exists: %v", err)
	}
}

func TestUnverifiedClientWithLiveAuthorizationIsNotEvicted(t *testing.T) {
	ctx := context.Background()
	store, err := sqlitestore.Open[struct{}](ctx, filepath.Join(t.TempDir(), "oauth.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	policy := lifecyclePolicy(t)
	old := lifecycleClient(t, "client-old", time.Now().UTC().Add(-2*time.Hour))
	if err := store.RegisterClient(ctx, old, policy); err != nil {
		t.Fatal(err)
	}
	token, _ := oauthserver.NewTransactionToken("transaction-000000000000000000000000000000000")
	if err := store.CreateAuthorization(ctx, oauthserver.AuthorizationTransaction{Token: token, ClientID: old.ID, RedirectURI: old.RedirectURIs[0], State: "state", Resource: "https://resource.example.test/api", ExpiresAt: time.Now().UTC().Add(time.Hour)}, policy); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterClient(ctx, lifecycleClient(t, "client-new", time.Now().UTC()), policy); !errors.Is(err, oauthserver.ErrCapacity) {
		t.Fatalf("live authorization client eviction error = %v", err)
	}
}

func lifecyclePolicy(t *testing.T) oauthserver.StatePolicy {
	t.Helper()
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	config.StatePolicy.Registration.MaxClients = 1
	config.StatePolicy.Registration.UnverifiedClientTTL = time.Hour
	return config.StatePolicy
}

func lifecycleClient(t *testing.T, id oauthserver.ClientID, lastUsed time.Time) oauthserver.Client {
	t.Helper()
	scopes, _ := oauthserver.NewScopeSet("read")
	return oauthserver.Client{ID: id, DisplayName: string(id), Trust: oauthserver.ClientTrustUnverified, RedirectURIs: []oauthserver.RedirectURI{"https://client.example.test/callback"}, AllowedScopes: scopes, CreatedAt: lastUsed, LastUsedAt: lastUsed}
}
