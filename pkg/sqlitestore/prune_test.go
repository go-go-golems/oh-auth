package sqlitestore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

func TestAdmissionPrunesExpiredTransientState(t *testing.T) {
	ctx := context.Background()
	clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	store, err := sqlitestore.Open[struct{}](ctx, filepath.Join(t.TempDir(), "oauth.db"), nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	policy := oauthserver.StatePolicy{Capacity: oauthserver.StateCapacity{MaxAuthorizations: 1}, Registration: oauthserver.RegistrationPolicy{MaxClients: 1}}
	first, _ := oauthserver.NewTransactionToken("expired-transaction-000000000000000000000")
	resource, _ := oauthserver.NewResourceID("https://resource.example.test/api")
	expired := oauthserver.AuthorizationTransaction{Token: first, ClientID: "client-1", RedirectURI: "https://client.example.test/callback", State: "state", Resource: resource, ExpiresAt: clock.Now().Add(-time.Minute)}
	if err := store.CreateAuthorization(ctx, expired, policy); err != nil {
		t.Fatal(err)
	}
	second, _ := oauthserver.NewTransactionToken("live-transaction-000000000000000000000000")
	live := expired
	live.Token = second
	live.ExpiresAt = clock.Now().Add(time.Minute)
	if err := store.CreateAuthorization(ctx, live, policy); err != nil {
		t.Fatalf("expired state blocked admission: %v", err)
	}
	counts, err := store.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Authorizations != 1 {
		t.Fatalf("authorization count = %d", counts.Authorizations)
	}
}
