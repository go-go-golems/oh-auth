#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/probe.go" <<'GO'
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/go-go-golems/oh-auth/pkg/oauthserver"
    "github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

func main() {
    ctx := context.Background()
    store, err := sqlitestore.Open[struct{}](ctx, os.Args[1], nil)
    if err != nil { panic(err) }
    defer func() { _ = store.Close() }()

    now := time.Now().UTC()
    scopes, _ := oauthserver.NewScopeSet("read")
    policy := oauthserver.StatePolicy{
        Registration: oauthserver.RegistrationPolicy{MaxClients: 4},
        Capacity: oauthserver.StateCapacity{MaxAuthorizations: 4, MaxConsents: 4, MaxCodes: 4, MaxRefreshGrants: 4},
    }
    client := oauthserver.Client{
        ID: "client-1", DisplayName: "client", RedirectURIs: []oauthserver.RedirectURI{"https://client.example/callback"},
        AllowedScopes: scopes, CreatedAt: now, LastUsedAt: now,
    }
    if err := store.RegisterClient(ctx, client, policy); err != nil { panic(err) }
    touched := now.Add(time.Hour)
    if err := store.TouchClient(ctx, client.ID, touched); err != nil { panic(err) }
    loaded, err := store.GetClient(ctx, client.ID)
    if err != nil { panic(err) }
    fmt.Printf("touch_visible_through_GetClient=%v\n", loaded.LastUsedAt.Equal(touched))

    transaction, _ := oauthserver.NewTransactionToken("review-transaction-credential-000000000000000000")
    resource, _ := oauthserver.NewResourceID("https://resource.example/api")
    auth := oauthserver.AuthorizationTransaction{
        Token: transaction, ClientID: client.ID, RedirectURI: client.RedirectURIs[0], State: "state",
        RequestedScopes: scopes, Resource: resource, ExpiresAt: now.Add(time.Hour),
    }
    if err := store.CreateAuthorization(ctx, auth, policy); err != nil { panic(err) }

    consent, _ := oauthserver.NewConsentToken("review-consent-credential-000000000000000000000")
    if err := store.CommitLogin(ctx, oauthserver.LoginCommit[struct{}]{
        TransactionDigest: oauthserver.DigestCredential(string(transaction)),
        Consent: oauthserver.ConsentSession[struct{}]{
            Token: consent, Client: oauthserver.ConsentClientSnapshot{ID: client.ID, RedirectURI: client.RedirectURIs[0]},
            Principal: oauthserver.Principal[struct{}]{Subject: "subject-1"}, Resource: resource, ExpiresAt: now.Add(time.Hour),
        },
    }, policy); err != nil { panic(err) }
}
GO

cd "$repo_root"
GOWORK=off go run "$tmp/probe.go" "$tmp/probe.db"
python3 - "$tmp/probe.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
checks = [
    ("oauth_authorizations", b"review-transaction-credential"),
    ("oauth_consents", b"review-consent-credential"),
]
for table, marker in checks:
    payload = connection.execute(f"SELECT payload FROM {table} LIMIT 1").fetchone()[0]
    print(f"{table}_contains_raw_credential={marker in payload}")
PY
