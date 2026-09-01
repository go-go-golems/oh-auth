package memorytest

import (
	"errors"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

func TestRefreshDigestCollisionsDoNotConsumePredecessor(t *testing.T) {
	clock := NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	store := NewStoreWithClock[struct{}](clock)
	scopes, _ := oauthserver.NewScopeSet("read")
	policy := oauthserver.StatePolicy{Capacity: oauthserver.StateCapacity{MaxRefreshGrants: 2, MaxRefreshGenerations: 10}}
	codeDigest := oauthserver.DigestCredential("code-000000000000000000000000000000000000")
	code := oauthserver.AuthorizationCodeRecord[struct{}]{Digest: codeDigest, ClientID: "client-1", Principal: oauthserver.Principal[struct{}]{Subject: "subject-1"}, Scopes: scopes, Resource: "https://resource.example.test/api", AuthorizationEnds: clock.Now().Add(time.Hour), ExpiresAt: clock.Now().Add(time.Minute)}
	store.codes[codeDigest] = code
	collision := oauthserver.DigestCredential("collision-000000000000000000000000000000000")
	store.refresh[collision] = oauthserver.RefreshGrant[struct{}]{Digest: collision, FamilyID: "other-family-000000000000000000000000000", ClientID: "other-client", ExpiresAt: clock.Now().Add(time.Hour)}
	grant := oauthserver.RefreshGrant[struct{}]{Digest: collision, FamilyID: "family-000000000000000000000000000000000000", ClientID: code.ClientID, Principal: code.Principal, Scopes: scopes, Resource: code.Resource, ExpiresAt: code.AuthorizationEnds}
	if err := store.CommitCodeExchange(t.Context(), oauthserver.CodeExchangeCommit[struct{}]{CodeDigest: codeDigest, Refresh: &grant}, policy); !errors.Is(err, oauthserver.ErrConflict) {
		t.Fatalf("code collision error = %v", err)
	}
	if !store.codes[codeDigest].ConsumedAt.IsZero() {
		t.Fatal("code was consumed after refresh digest collision")
	}

	currentDigest := oauthserver.DigestCredential("current-00000000000000000000000000000000000")
	current := grant
	current.Digest = currentDigest
	store.refresh[currentDigest] = current
	successor := current
	successor.Digest = collision
	successor.Generation = 1
	if err := store.CommitRefreshRotation(t.Context(), oauthserver.RefreshRotation[struct{}]{CurrentDigest: currentDigest, FamilyID: current.FamilyID, Generation: 0, Successor: successor}, policy); !errors.Is(err, oauthserver.ErrConflict) {
		t.Fatalf("rotation collision error = %v", err)
	}
	if !store.refresh[currentDigest].ConsumedAt.IsZero() {
		t.Fatal("refresh grant was consumed after successor digest collision")
	}
}
