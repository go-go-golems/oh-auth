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
	if _, err := db.ExecContext(ctx, "UPDATE oauth_schema_version SET version=2"); err != nil {
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
