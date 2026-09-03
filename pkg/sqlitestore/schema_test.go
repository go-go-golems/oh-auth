package sqlitestore_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

func TestOpenRejectsUnsupportedSchemaVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oauth.db")
	store, err := sqlitestore.Open[struct{}](ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE oauth_schema_version SET version=3"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := sqlitestore.Open[struct{}](ctx, path, nil); err == nil {
		_ = reopened.Close()
		t.Fatal("unsupported schema version accepted")
	}
}

func TestOpenMigratesLegacyClientsLastUsedAt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oauth.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
CREATE TABLE oauth_schema_version (version INTEGER NOT NULL);
INSERT INTO oauth_schema_version(version) VALUES (1);
CREATE TABLE oauth_clients (id TEXT PRIMARY KEY, payload BLOB NOT NULL, created_at TEXT NOT NULL);
INSERT INTO oauth_clients(id, payload, created_at) VALUES ('legacy-client', '{}', '2026-09-03T00:00:00Z');
`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := sqlitestore.Open[struct{}](ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var version int
	if err := db.QueryRowContext(ctx, "SELECT version FROM oauth_schema_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("schema version = %d, want 2", version)
	}
	var lastUsed string
	if err := db.QueryRowContext(ctx, "SELECT last_used_at FROM oauth_clients WHERE id='legacy-client'").Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed != "2026-09-03T00:00:00Z" {
		t.Fatalf("last_used_at = %q", lastUsed)
	}

	// Opening again proves the migration is idempotent.
	reopened, err := sqlitestore.Open[struct{}](ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
