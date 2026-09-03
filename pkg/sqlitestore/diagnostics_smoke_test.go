package sqlitestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

func TestDiagnosticsSmoke(t *testing.T) {
	store, err := sqlitestore.Open[map[string]any](context.Background(), t.TempDir()+"/diag.sqlite", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.RegisterClient(context.Background(), oauthserver.Client{ID: "client-x", DisplayName: "x", RedirectURIs: []oauthserver.RedirectURI{"https://example.com/cb"}, CreatedAt: time.Now().UTC(), LastUsedAt: time.Now().UTC()}, oauthserver.StatePolicy{Registration: oauthserver.RegistrationPolicy{MaxClients: 10, MaxDisplayName: 64, MaxRedirectURIs: 4, MaxRedirectBytes: 512, MaxScopeCount: 8, UnverifiedClientTTL: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	diagnostics, err := store.Diagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.SchemaVersion != 1 || diagnostics.JournalMode != "wal" || !diagnostics.ForeignKeys || diagnostics.BusyTimeoutMs != 5000 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if diagnostics.Counts.Clients != 1 || !diagnostics.WriteProbeOK || diagnostics.DatabaseBytes == 0 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
}
