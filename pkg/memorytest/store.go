// Package memorytest provides deterministic in-memory implementations for tests and examples.
package memorytest

import (
	"context"
	"sync"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type Store[A any] struct {
	mu          sync.Mutex
	clock       oauthserver.Clock
	clients     map[oauthserver.ClientID]oauthserver.Client
	authorizers map[oauthserver.CredentialDigest]oauthserver.AuthorizationTransaction
	consents    map[oauthserver.CredentialDigest]oauthserver.ConsentSession[A]
	codes       map[oauthserver.CredentialDigest]oauthserver.AuthorizationCodeRecord[A]
	refresh     map[oauthserver.CredentialDigest]oauthserver.RefreshGrant[A]
}

func NewStore[A any]() *Store[A] {
	return NewStoreWithClock[A](oauthserver.SystemClock{})
}

func NewStoreWithClock[A any](clock oauthserver.Clock) *Store[A] {
	if clock == nil {
		panic("memory store clock is required")
	}
	return &Store[A]{clock: clock, clients: make(map[oauthserver.ClientID]oauthserver.Client), authorizers: make(map[oauthserver.CredentialDigest]oauthserver.AuthorizationTransaction), consents: make(map[oauthserver.CredentialDigest]oauthserver.ConsentSession[A]), codes: make(map[oauthserver.CredentialDigest]oauthserver.AuthorizationCodeRecord[A]), refresh: make(map[oauthserver.CredentialDigest]oauthserver.RefreshGrant[A])}
}

func (s *Store[A]) RegisterClient(_ context.Context, client oauthserver.Client, policy oauthserver.StatePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now().UTC()
	for id, existing := range s.clients {
		if existing.Trust == oauthserver.ClientTrustUnverified && !existing.LastUsedAt.After(now.Add(-policy.Registration.UnverifiedClientTTL)) && !s.clientHasLiveStateLocked(id, now) {
			delete(s.clients, id)
		}
	}
	if len(s.clients) >= policy.Registration.MaxClients {
		return oauthserver.ErrCapacity
	}
	if _, exists := s.clients[client.ID]; exists {
		return oauthserver.ErrConflict
	}
	s.clients[client.ID] = cloneClient(client)
	return nil
}
func (s *Store[A]) GetClient(_ context.Context, id oauthserver.ClientID) (oauthserver.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	if !ok {
		return oauthserver.Client{}, oauthserver.ErrNotFound
	}
	return cloneClient(client), nil
}
func (s *Store[A]) TouchClient(_ context.Context, id oauthserver.ClientID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	if !ok {
		return oauthserver.ErrNotFound
	}
	client.LastUsedAt = at
	s.clients[id] = client
	return nil
}
func (s *Store[A]) CreateAuthorization(_ context.Context, state oauthserver.AuthorizationTransaction, policy oauthserver.StatePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.clock.Now().UTC())
	if len(s.authorizers) >= policy.Capacity.MaxAuthorizations {
		return oauthserver.ErrCapacity
	}
	digest := oauthserver.DigestCredential(string(state.Token))
	if _, ok := s.authorizers[digest]; ok {
		return oauthserver.ErrConflict
	}
	s.authorizers[digest] = state
	return nil
}
func (s *Store[A]) GetAuthorization(_ context.Context, digest oauthserver.CredentialDigest) (oauthserver.AuthorizationTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.authorizers[digest]
	if !ok {
		return oauthserver.AuthorizationTransaction{}, oauthserver.ErrNotFound
	}
	return state, nil
}
func (s *Store[A]) CommitLogin(_ context.Context, commit oauthserver.LoginCommit[A], policy oauthserver.StatePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.clock.Now().UTC())
	state, ok := s.authorizers[commit.TransactionDigest]
	if !ok {
		return oauthserver.ErrNotFound
	}
	now := s.clock.Now().UTC()
	if err := oauthserver.ValidateLoginCommit(state, commit.Consent, now); err != nil {
		return err
	}
	if len(s.consents) >= policy.Capacity.MaxConsents {
		return oauthserver.ErrCapacity
	}
	consentDigest := oauthserver.DigestCredential(string(commit.Consent.Token))
	if _, exists := s.consents[consentDigest]; exists {
		return oauthserver.ErrConflict
	}
	state.ConsumedAt = now
	s.authorizers[commit.TransactionDigest] = state
	s.consents[consentDigest] = commit.Consent
	return nil
}
func (s *Store[A]) GetConsent(_ context.Context, digest oauthserver.CredentialDigest) (oauthserver.ConsentSession[A], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	consent, ok := s.consents[digest]
	if !ok {
		return oauthserver.ConsentSession[A]{}, oauthserver.ErrNotFound
	}
	return consent, nil
}
func (s *Store[A]) CommitConsent(_ context.Context, commit oauthserver.ConsentCommit[A], policy oauthserver.StatePolicy) (oauthserver.ConsentCommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.clock.Now().UTC())
	consent, ok := s.consents[commit.ConsentDigest]
	if !ok {
		return oauthserver.ConsentCommitResult{}, oauthserver.ErrNotFound
	}
	now := s.clock.Now().UTC()
	if err := oauthserver.ValidateConsentCommit(consent, commit, now); err != nil {
		return oauthserver.ConsentCommitResult{}, err
	}
	if commit.Decision == oauthserver.ConsentDecisionApprove {
		if len(s.codes) >= policy.Capacity.MaxCodes {
			return oauthserver.ConsentCommitResult{}, oauthserver.ErrCapacity
		}
		digest := commit.Code.Digest
		if _, exists := s.codes[digest]; exists {
			return oauthserver.ConsentCommitResult{}, oauthserver.ErrConflict
		}
		s.codes[digest] = commit.Code
	}
	consent.ConsumedAt = now
	s.consents[commit.ConsentDigest] = consent
	return oauthserver.ConsentCommitResult{RedirectURI: string(consent.Client.RedirectURI)}, nil
}
func (s *Store[A]) GetCodeForExchange(_ context.Context, binding oauthserver.CodeExchangeBinding) (oauthserver.AuthorizationCodeRecord[A], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.codes[binding.Digest]
	if !ok {
		return oauthserver.AuthorizationCodeRecord[A]{}, oauthserver.ErrNotFound
	}
	if code.ClientID != binding.ClientID || code.RedirectURI != binding.RedirectURI {
		return oauthserver.AuthorizationCodeRecord[A]{}, oauthserver.ErrBinding
	}
	return code, nil
}
func (s *Store[A]) CommitCodeExchange(_ context.Context, commit oauthserver.CodeExchangeCommit[A], policy oauthserver.StatePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.clock.Now().UTC())
	code, ok := s.codes[commit.CodeDigest]
	if !ok {
		return oauthserver.ErrNotFound
	}
	now := s.clock.Now().UTC()
	if err := oauthserver.ValidateCodeExchangeCommit(code, commit, now); err != nil {
		return err
	}
	if s.activeRefreshGrantCountLocked() >= policy.Capacity.MaxRefreshGrants {
		return oauthserver.ErrCapacity
	}
	code.ConsumedAt = now
	s.codes[commit.CodeDigest] = code
	s.refresh[commit.Refresh.Digest] = *commit.Refresh
	return nil
}
func (s *Store[A]) GetRefreshGrant(_ context.Context, digest oauthserver.CredentialDigest) (oauthserver.RefreshGrant[A], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.refresh[digest]
	if !ok {
		return oauthserver.RefreshGrant[A]{}, oauthserver.ErrNotFound
	}
	return grant, nil
}
func (s *Store[A]) CommitRefreshRotation(_ context.Context, rotation oauthserver.RefreshRotation[A], policy oauthserver.StatePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.clock.Now().UTC())
	current, ok := s.refresh[rotation.CurrentDigest]
	if !ok {
		return oauthserver.ErrNotFound
	}
	now := s.clock.Now().UTC()
	if current.FamilyID != rotation.FamilyID || current.Generation != rotation.Generation {
		return oauthserver.ErrBinding
	}
	if !current.ConsumedAt.IsZero() || !current.RevokedAt.IsZero() {
		s.revokeFamilyLocked(rotation.FamilyID, now)
		return oauthserver.ErrRevoked
	}
	if err := oauthserver.ValidateRefreshRotation(current, rotation, now); err != nil {
		return err
	}
	if rotation.Successor.Generation >= policy.Capacity.MaxRefreshGenerations {
		s.revokeFamilyLocked(rotation.FamilyID, now)
		return oauthserver.ErrRevoked
	}
	current.ConsumedAt = now
	s.refresh[rotation.CurrentDigest] = current
	s.refresh[rotation.Successor.Digest] = rotation.Successor
	return nil
}
func (s *Store[A]) activeRefreshGrantCountLocked() int {
	count := 0
	for _, grant := range s.refresh {
		if grant.ConsumedAt.IsZero() && grant.RevokedAt.IsZero() {
			count++
		}
	}
	return count
}

func (s *Store[A]) RevokeRefreshFamily(_ context.Context, family oauthserver.RefreshFamilyID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(family, at)
	return nil
}
func (s *Store[A]) revokeFamilyLocked(family oauthserver.RefreshFamilyID, at time.Time) {
	for digest, grant := range s.refresh {
		if grant.FamilyID == family && grant.RevokedAt.IsZero() {
			grant.RevokedAt = at
			s.refresh[digest] = grant
		}
	}
}
func (s *Store[A]) Prune(_ context.Context, _ oauthserver.StatePolicy) (oauthserver.PruneStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneExpiredLocked(s.clock.Now().UTC()), nil
}

func (s *Store[A]) pruneExpiredLocked(now time.Time) oauthserver.PruneStats {
	stats := oauthserver.PruneStats{}
	for digest, state := range s.authorizers {
		if !state.ExpiresAt.After(now) {
			delete(s.authorizers, digest)
			stats.Authorizations++
		}
	}
	for digest, consent := range s.consents {
		if !consent.ExpiresAt.After(now) {
			delete(s.consents, digest)
			stats.Consents++
		}
	}
	for digest, code := range s.codes {
		if !code.ExpiresAt.After(now) {
			delete(s.codes, digest)
			stats.Codes++
		}
	}
	familyExpiry := make(map[oauthserver.RefreshFamilyID]time.Time)
	for _, grant := range s.refresh {
		if grant.ExpiresAt.After(familyExpiry[grant.FamilyID]) {
			familyExpiry[grant.FamilyID] = grant.ExpiresAt
		}
	}
	for digest, grant := range s.refresh {
		if !familyExpiry[grant.FamilyID].After(now) {
			delete(s.refresh, digest)
			stats.RefreshGrants++
		}
	}
	return stats
}
func (s *Store[A]) clientHasLiveStateLocked(id oauthserver.ClientID, now time.Time) bool {
	for _, state := range s.authorizers {
		if state.ClientID == id && state.ConsumedAt.IsZero() && state.ExpiresAt.After(now) {
			return true
		}
	}
	for _, consent := range s.consents {
		if consent.Client.ID == id && consent.ConsumedAt.IsZero() && consent.ExpiresAt.After(now) {
			return true
		}
	}
	for _, code := range s.codes {
		if code.ClientID == id && code.ConsumedAt.IsZero() && code.ExpiresAt.After(now) {
			return true
		}
	}
	for _, grant := range s.refresh {
		if grant.ClientID == id && grant.RevokedAt.IsZero() && grant.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func (s *Store[A]) Counts(_ context.Context) (oauthserver.StateCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return oauthserver.StateCounts{Clients: len(s.clients), Authorizations: len(s.authorizers), Consents: len(s.consents), Codes: len(s.codes), RefreshGrants: len(s.refresh)}, nil
}

func cloneClient(client oauthserver.Client) oauthserver.Client {
	client.RedirectURIs = append([]oauthserver.RedirectURI(nil), client.RedirectURIs...)
	client.AllowedScopes, _ = oauthserver.NewScopeSet(client.AllowedScopes.Values()...)
	return client
}

var _ oauthserver.Store[struct{}] = (*Store[struct{}])(nil)
