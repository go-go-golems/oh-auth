package oauthserver_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	"github.com/go-go-golems/oh-auth/pkg/sqlitestore"
)

type conformanceStore struct {
	oauthserver.Store[struct{}]
	close func() error
}

func TestStoreConformance(t *testing.T) {
	for name, factory := range map[string]func(*testing.T, oauthserver.Clock) conformanceStore{
		"memory": func(t *testing.T, clock oauthserver.Clock) conformanceStore {
			return conformanceStore{Store: memorytest.NewStoreWithClock[struct{}](clock), close: func() error { return nil }}
		},
		"sqlite": func(t *testing.T, clock oauthserver.Clock) conformanceStore {
			store, err := sqlitestore.Open[struct{}](t.Context(), filepath.Join(t.TempDir(), "oauth.db"), nil, clock)
			if err != nil {
				t.Fatal(err)
			}
			return conformanceStore{Store: store, close: store.Close}
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
			store := factory(t, clock)
			defer func() { _ = store.close() }()
			runExpiryAdmissionConformance(t, store.Store, clock)
		})
		t.Run(name+"/binding-retry", func(t *testing.T) {
			clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
			store := factory(t, clock)
			defer func() { _ = store.close() }()
			runBindingRetryConformance(t, store.Store, clock)
		})
		t.Run(name+"/concurrent-capacity", func(t *testing.T) {
			clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
			store := factory(t, clock)
			defer func() { _ = store.close() }()
			runConcurrentCapacityConformance(t, store.Store, clock)
		})
	}
}

func conformancePolicy(t *testing.T) oauthserver.StatePolicy {
	t.Helper()
	scopes, _ := oauthserver.NewScopeSet("read")
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: "https://resource.example.test/api", DisplayName: "resource", SupportedScopes: []string{"read"}}}, scopes)
	config.StatePolicy.Capacity.MaxAuthorizations = 1
	return config.StatePolicy
}

func conformanceAuthorization(t *testing.T, raw string, expiry time.Time) oauthserver.AuthorizationTransaction {
	t.Helper()
	token, err := oauthserver.NewTransactionToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := oauthserver.NewScopeSet("read")
	challenge, _ := oauthserver.NewPKCEChallenge("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "S256")
	return oauthserver.AuthorizationTransaction{Token: token, ClientID: "client-1", RedirectURI: "https://client.example.test/callback", State: "state", PKCEChallenge: challenge, RequestedScopes: scopes, Resource: "https://resource.example.test/api", ExpiresAt: expiry}
}

func runExpiryAdmissionConformance(t *testing.T, store oauthserver.Store[struct{}], clock *memorytest.Clock) {
	t.Helper()
	policy := conformancePolicy(t)
	first := conformanceAuthorization(t, "transaction-first-000000000000000000000000000", clock.Now().Add(time.Minute))
	second := conformanceAuthorization(t, "transaction-second-00000000000000000000000000", clock.Now().Add(3*time.Minute))
	if err := store.CreateAuthorization(t.Context(), first, policy); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAuthorization(t.Context(), second, policy); !errors.Is(err, oauthserver.ErrCapacity) {
		t.Fatalf("pre-expiry admission error = %v", err)
	}
	clock.Advance(2 * time.Minute)
	if err := store.CreateAuthorization(t.Context(), second, policy); err != nil {
		t.Fatalf("expired state did not release capacity: %v", err)
	}
}

func runBindingRetryConformance(t *testing.T, store oauthserver.Store[struct{}], clock *memorytest.Clock) {
	t.Helper()
	policy := conformancePolicy(t)
	auth := conformanceAuthorization(t, "transaction-binding-0000000000000000000000000", clock.Now().Add(time.Minute))
	if err := store.CreateAuthorization(t.Context(), auth, policy); err != nil {
		t.Fatal(err)
	}
	consentToken, _ := oauthserver.NewConsentToken("consent-binding-000000000000000000000000000")
	consent := oauthserver.ConsentSession[struct{}]{Token: consentToken, Client: oauthserver.ConsentClientSnapshot{ID: auth.ClientID, RedirectURI: auth.RedirectURI}, State: auth.State, PKCEChallenge: auth.PKCEChallenge, Principal: oauthserver.Principal[struct{}]{Subject: "subject-1"}, AllowedScopes: auth.RequestedScopes, Resource: auth.Resource, AuthorizationEnds: clock.Now().Add(time.Hour), ExpiresAt: clock.Now().Add(time.Minute)}
	forged := consent
	forged.Resource = "https://attacker.example.test/api"
	digest := oauthserver.DigestCredential(string(auth.Token))
	if err := store.CommitLogin(t.Context(), oauthserver.LoginCommit[struct{}]{TransactionDigest: digest, Consent: forged}, policy); !errors.Is(err, oauthserver.ErrBinding) {
		t.Fatalf("forged login error = %v", err)
	}
	if err := store.CommitLogin(t.Context(), oauthserver.LoginCommit[struct{}]{TransactionDigest: digest, Consent: consent}, policy); err != nil {
		t.Fatalf("valid retry failed: %v", err)
	}
}

func runConcurrentCapacityConformance(t *testing.T, store oauthserver.Store[struct{}], clock *memorytest.Clock) {
	t.Helper()
	policy := conformancePolicy(t)
	states := []oauthserver.AuthorizationTransaction{
		conformanceAuthorization(t, "transaction-race-a-00000000000000000000000000", clock.Now().Add(time.Minute)),
		conformanceAuthorization(t, "transaction-race-b-00000000000000000000000000", clock.Now().Add(time.Minute)),
	}
	results := make(chan error, len(states))
	var wait sync.WaitGroup
	for _, state := range states {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- store.CreateAuthorization(t.Context(), state, policy)
		}()
	}
	wait.Wait()
	close(results)
	successes, capacities := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, oauthserver.ErrCapacity):
			capacities++
		default:
			t.Fatalf("unexpected concurrent admission error: %v", err)
		}
	}
	if successes != 1 || capacities != 1 {
		t.Fatalf("concurrent results successes=%d capacities=%d", successes, capacities)
	}
}
