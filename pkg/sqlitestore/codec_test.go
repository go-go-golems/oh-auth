package sqlitestore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

type opaqueCodec struct{}

func (opaqueCodec) EncodePrincipal(oauthserver.Principal[struct{}]) ([]byte, error) {
	return []byte{0xff, 0x00, 0x01}, nil
}
func (opaqueCodec) DecodePrincipal([]byte) (oauthserver.Principal[struct{}], error) {
	return oauthserver.Principal[struct{}]{Subject: "decoded"}, nil
}

func TestPrincipalCodecMayReturnNonJSONBytes(t *testing.T) {
	ctx := context.Background()
	store, err := sqlitestore.Open(ctx, filepath.Join(t.TempDir(), "oauth.db"), opaqueCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	policy := oauthserver.StatePolicy{Capacity: oauthserver.StateCapacity{MaxAuthorizations: 2, MaxConsents: 2}, Retention: oauthserver.RetentionPolicy{ConsumedState: time.Hour}}
	txToken, _ := oauthserver.NewTransactionToken("transaction-opaque-000000000000000000")
	resource, _ := oauthserver.NewResourceID("https://resource.example.test/api")
	challenge, _ := oauthserver.NewPKCEChallenge("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "S256")
	if err := store.CreateAuthorization(ctx, oauthserver.AuthorizationTransaction{Token: txToken, ClientID: "client-1", RedirectURI: "https://client.example.test/callback", State: "state", PKCEChallenge: challenge, Resource: resource, ExpiresAt: time.Now().UTC().Add(time.Minute)}, policy); err != nil {
		t.Fatal(err)
	}
	consentToken, _ := oauthserver.NewConsentToken("consent-opaque-000000000000000000000")
	if err := store.CommitLogin(ctx, oauthserver.LoginCommit[struct{}]{TransactionDigest: oauthserver.DigestCredential(string(txToken)), Consent: oauthserver.ConsentSession[struct{}]{Token: consentToken, Client: oauthserver.ConsentClientSnapshot{ID: "client-1", RedirectURI: "https://client.example.test/callback"}, Principal: oauthserver.Principal[struct{}]{Subject: "original"}, Resource: resource, ExpiresAt: time.Now().UTC().Add(time.Minute)}}, policy); err != nil {
		t.Fatal(err)
	}
	consent, err := store.GetConsent(ctx, oauthserver.DigestCredential(string(consentToken)))
	if err != nil {
		t.Fatal(err)
	}
	if consent.Principal.Subject != "decoded" {
		t.Fatalf("decoded principal = %+v", consent.Principal)
	}
}
