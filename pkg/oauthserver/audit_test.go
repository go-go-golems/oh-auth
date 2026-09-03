package oauthserver_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/correlation"
	"github.com/go-go-golems/oh-auth/pkg/memorytest"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type capturingSink struct{ events []oauthserver.AuditEvent }

func (s *capturingSink) Record(_ context.Context, event oauthserver.AuditEvent) {
	s.events = append(s.events, event)
}

func (s *capturingSink) find(operation, outcome string) *oauthserver.AuditEvent {
	for i := range s.events {
		if s.events[i].Operation == operation && s.events[i].Outcome == outcome {
			return &s.events[i]
		}
	}
	return nil
}

type failingTransactionSecrets struct{ inner *memorytest.Secrets }

func (s failingTransactionSecrets) NewClientID() (oauthserver.ClientID, error) {
	return s.inner.NewClientID()
}

func (s failingTransactionSecrets) NewTransactionToken() (oauthserver.TransactionToken, error) {
	return "", errors.New("entropy source unavailable")
}

func (s failingTransactionSecrets) NewConsentToken() (oauthserver.ConsentToken, error) {
	return s.inner.NewConsentToken()
}

func (s failingTransactionSecrets) NewAuthorizationCode() (oauthserver.AuthorizationCode, error) {
	return s.inner.NewAuthorizationCode()
}

func (s failingTransactionSecrets) NewRefreshToken() (oauthserver.RefreshToken, error) {
	return s.inner.NewRefreshToken()
}

func (s failingTransactionSecrets) NewRefreshFamilyID() (oauthserver.RefreshFamilyID, error) {
	return s.inner.NewRefreshFamilyID()
}

func newAuditTestEngine(t *testing.T, sink oauthserver.AuditSink) (*oauthserver.Engine[struct{}], *memorytest.Store[struct{}], oauthserver.Principal[struct{}], string) {
	engine, store, principal, resourceID, _ := newAuditTestEngineParts(t, sink, &memorytest.Secrets{})
	return engine, store, principal, resourceID
}

// newAuditTestEngineParts builds a full engine with overridable secrets so
// tests can force server-side failures (for example secret generation). The
// returned rebuild closure constructs a fresh engine over the same fixtures
// with a custom store, for testing store read failures.
func newAuditTestEngineParts(t *testing.T, sink oauthserver.AuditSink, secrets oauthserver.SecretSource) (*oauthserver.Engine[struct{}], *memorytest.Store[struct{}], oauthserver.Principal[struct{}], string, func(oauthserver.Store[struct{}]) *oauthserver.Engine[struct{}]) {
	t.Helper()
	scopes, _ := oauthserver.NewScopeSet("documents:read")
	resourceID := "https://rag.example.test/api"
	config := oauthserver.DefaultConfig("https://auth.example.test", []oauthserver.ResourceConfig{{ID: resourceID, DisplayName: "RAG", SupportedScopes: []string{"documents:read"}}}, scopes)
	clock := memorytest.NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	store := memorytest.NewStoreWithClock[struct{}](clock)
	resources, err := oauthserver.NewStaticResourceRegistry(config.Resources, config.SupportedScopes)
	if err != nil {
		t.Fatal(err)
	}
	principal := oauthserver.Principal[struct{}]{Subject: oauthserver.Subject("employee-1")}
	revalidator := &memorytest.Revalidator[struct{}]{Result: oauthserver.Revalidation[struct{}]{Status: oauthserver.RevalidationEligible, Principal: principal}}
	newEngine := func(store oauthserver.Store[struct{}]) *oauthserver.Engine[struct{}] {
		t.Helper()
		engine, err := oauthserver.New(config, oauthserver.Dependencies[struct{}]{Store: store, Resources: resources, Scopes: memorytest.ScopePolicy[struct{}]{Available: scopes}, Revalidator: revalidator, Tokens: &memorytest.TokenService[struct{}]{Issuer: config.Issuer}, Secrets: secrets, Clock: clock, Audit: sink})
		if err != nil {
			t.Fatal(err)
		}
		return engine
	}
	engine := newEngine(store)
	clientID := "client-known"
	if err := store.RegisterClient(context.Background(), oauthserver.Client{ID: oauthserver.ClientID(clientID), DisplayName: "Known", RedirectURIs: []oauthserver.RedirectURI{"https://client.example.test/callback"}, AllowedScopes: scopes, CreatedAt: clock.Now().UTC(), LastUsedAt: clock.Now().UTC()}, config.StatePolicy); err != nil {
		t.Fatal(err)
	}
	return engine, store, principal, resourceID, newEngine
}

func auditTestVerifierChallenge() string {
	digest := oauthserver.DigestCredential(strings.Repeat("v", 43))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// TestAuditDeniedFields asserts the exact safe field contract of a denial
// event: typed identifiers, a reason code, and the correlation identifier, but
// no credential material (which the event type cannot carry by construction).
func TestAuditDeniedFields(t *testing.T) {
	ctx := correlation.WithID(context.Background(), "req-12345678")
	sink := &capturingSink{}
	engine, _, _, resourceID := newAuditTestEngine(t, sink)
	_, err := engine.BeginAuthorization(ctx, oauthserver.BeginAuthorizationInput{ClientID: "client-missing", RedirectURI: "https://client.example.test/callback", ResponseType: "code", State: "state-1", CodeChallenge: auditTestVerifierChallenge(), ChallengeMethod: "S256", Scopes: []string{"documents:read"}, Resource: resourceID})
	if err == nil {
		t.Fatal("expected denial")
	}
	event := sink.find("begin_authorization", "denied")
	if event == nil {
		t.Fatalf("expected denied audit event, got %+v", sink.events)
	}
	if event.ReasonCode != "store_not_found" {
		t.Fatalf("reason code = %q", event.ReasonCode)
	}
	if event.RequestID != "req-12345678" {
		t.Fatalf("request id = %q", event.RequestID)
	}
	if event.ClientID != "client-missing" || event.Resource != oauthserver.ResourceID(resourceID) {
		t.Fatalf("unexpected identifiers: %+v", event)
	}
	if event.Cause != nil {
		t.Fatal("denied events must not carry a cause")
	}
}

// TestAuditErrorCarriesTrustedCause asserts that server-side failures record
// an error outcome with a non-nil cause and a stable reason classification.
func TestAuditErrorCarriesTrustedCause(t *testing.T) {
	ctx := correlation.WithID(context.Background(), "req-87654321")
	sink := &capturingSink{}
	engine, _, _, resourceID, _ := newAuditTestEngineParts(t, sink, failingTransactionSecrets{inner: &memorytest.Secrets{}})
	_, err := engine.BeginAuthorization(ctx, oauthserver.BeginAuthorizationInput{ClientID: "client-known", RedirectURI: "https://client.example.test/callback", ResponseType: "code", State: "state-1", CodeChallenge: auditTestVerifierChallenge(), ChallengeMethod: "S256", Scopes: []string{"documents:read"}, Resource: resourceID})
	if err == nil {
		t.Fatal("expected failure")
	}
	event := sink.find("begin_authorization", "error")
	if event == nil {
		t.Fatalf("expected an error audit event, got %+v", sink.events)
	}
	if event.ReasonCode != "secret_generation" {
		t.Fatalf("reason code = %q", event.ReasonCode)
	}
	if event.Cause == nil || event.Cause.Error() != "entropy source unavailable" {
		t.Fatalf("cause = %v", event.Cause)
	}
	if event.RequestID != "req-87654321" {
		t.Fatalf("request id = %q", event.RequestID)
	}
	// A malformed client ID is a denial, not an internal error.
	if event := sink.find("begin_authorization", "denied"); event != nil {
		t.Fatalf("unexpected denial event: %+v", event)
	}
}

// TestAuditLifecycleNeverLeaksCredentials runs a full successful lifecycle
// and asserts that every recorded event references only safe identifiers:
// the raw transaction, consent token, authorization code, and refresh token
// never appear in any event field.
func TestAuditLifecycleNeverLeaksCredentials(t *testing.T) {
	ctx := correlation.WithID(context.Background(), "req-abcdefgh")
	sink := &capturingSink{}
	engine, _, principal, resourceID := newAuditTestEngine(t, sink)
	registered, err := engine.RegisterClient(ctx, oauthserver.RegisterClientInput{DisplayName: "Client", RedirectURIs: []string{"https://client.example.test/callback"}, RequestedScopes: []string{"documents:read"}})
	if err != nil {
		t.Fatal(err)
	}
	started, err := engine.BeginAuthorization(ctx, oauthserver.BeginAuthorizationInput{ClientID: string(registered.Client.ID), RedirectURI: "https://client.example.test/callback", ResponseType: "code", State: "state-1", CodeChallenge: auditTestVerifierChallenge(), ChallengeMethod: "S256", Scopes: []string{"documents:read"}, Resource: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := engine.CompleteLogin(ctx, oauthserver.CompleteLoginInput[struct{}]{Transaction: started.Transaction, Principal: principal})
	if err != nil {
		t.Fatal(err)
	}
	decided, err := engine.DecideConsent(ctx, oauthserver.DecideConsentInput{Token: completed.ConsentToken, Decision: oauthserver.ConsentDecisionApprove, SelectedScopes: []oauthserver.Scope{"documents:read"}})
	if err != nil {
		t.Fatal(err)
	}
	code := ""
	if parsed, err := url.Parse(decided.RedirectURI); err == nil {
		code = parsed.Query().Get("code")
	}
	if code == "" {
		t.Fatal("authorization code missing from redirect")
	}
	secrets := []string{string(started.Transaction), string(completed.ConsentToken), code, strings.Repeat("v", 43), "state-1"}
	if len(sink.events) == 0 {
		t.Fatal("expected audit events")
	}
	for _, event := range sink.events {
		if event.RequestID != "req-abcdefgh" {
			t.Fatalf("request id = %q", event.RequestID)
		}
		blob := event.Operation + "|" + event.Outcome + "|" + event.ReasonCode + "|" + string(event.Subject) + "|" + string(event.ClientID) + "|" + string(event.Resource) + "|" + event.Scopes.String()
		for _, secret := range secrets {
			if secret != "" && strings.Contains(blob, secret) {
				t.Fatalf("audit event leaked credential material %q in %q", secret, blob)
			}
		}
	}
}

// brokenReadStore wraps the memory store and makes client reads fail with an
// unclassified operational error, as a closed database or SQLite I/O error
// would in production.
type brokenReadStore struct {
	*memorytest.Store[struct{}]
}

func (s brokenReadStore) GetClient(_ context.Context, _ oauthserver.ClientID) (oauthserver.Client, error) {
	return oauthserver.Client{}, errors.New("sqlite: disk I/O error")
}

// TestAuditUnclassifiedStoreReadIsError asserts that operational store read
// failures (not one of the expected state denials) are recorded as error
// events with a cause, so outages surface in server-error metrics.
func TestAuditUnclassifiedStoreReadIsError(t *testing.T) {
	ctx := correlation.WithID(context.Background(), "req-aaaaaaaa")
	sink := &capturingSink{}
	_, store, _, _, newEngine := newAuditTestEngineParts(t, sink, &memorytest.Secrets{})
	brokenEngine := newEngine(brokenReadStore{Store: store})
	_, err := brokenEngine.BeginAuthorization(ctx, oauthserver.BeginAuthorizationInput{ClientID: "client-any", RedirectURI: "https://client.example.test/callback", ResponseType: "code", State: "state-1", CodeChallenge: auditTestVerifierChallenge(), ChallengeMethod: "S256", Scopes: []string{"documents:read"}, Resource: "https://rag.example.test/api"})
	if err == nil {
		t.Fatal("expected failure")
	}
	event := sink.find("begin_authorization", "error")
	if event == nil {
		t.Fatalf("expected an error audit event, got %+v", sink.events)
	}
	if event.ReasonCode != "store_error" {
		t.Fatalf("reason code = %q", event.ReasonCode)
	}
	if event.Cause == nil || event.Cause.Error() != "sqlite: disk I/O error" {
		t.Fatalf("cause = %v", event.Cause)
	}
	if event.RequestID != "req-aaaaaaaa" {
		t.Fatalf("request id = %q", event.RequestID)
	}
}
func TestAuditStoreNotFoundClassification(t *testing.T) {
	ctx := context.Background()
	sink := &capturingSink{}
	engine, _, _, _ := newAuditTestEngine(t, sink)
	_, err := engine.BeginAuthorization(ctx, oauthserver.BeginAuthorizationInput{ClientID: "client-capacity", RedirectURI: "https://client.example.test/callback", ResponseType: "code", State: "state-1", CodeChallenge: auditTestVerifierChallenge(), ChallengeMethod: "S256", Scopes: []string{"documents:read"}, Resource: "https://rag.example.test/api"})
	if err == nil {
		t.Fatal("expected failure")
	}
	if event := sink.find("begin_authorization", "denied"); event == nil || event.ReasonCode != "store_not_found" {
		t.Fatalf("expected store_not_found classification, got %+v", sink.events)
	}
}
