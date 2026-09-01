// Package sqlitestore provides a bounded durable OAuth state store.
package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	_ "modernc.org/sqlite"
)

type Store[A any] struct {
	db    *sql.DB
	codec oauthserver.PrincipalCodec[A]
}

type JSONPrincipalCodec[A any] struct{}

func (JSONPrincipalCodec[A]) EncodePrincipal(principal oauthserver.Principal[A]) ([]byte, error) {
	return json.Marshal(principal)
}
func (JSONPrincipalCodec[A]) DecodePrincipal(data []byte) (oauthserver.Principal[A], error) {
	var principal oauthserver.Principal[A]
	err := json.Unmarshal(data, &principal)
	return principal, err
}

func Open[A any](ctx context.Context, path string, codec oauthserver.PrincipalCodec[A]) (*Store[A], error) {
	if codec == nil {
		codec = JSONPrincipalCodec[A]{}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store[A]{db: db, codec: codec}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store[A]) Close() error { return s.db.Close() }

func (s *Store[A]) configure(ctx context.Context) error {
	for _, statement := range []string{"PRAGMA foreign_keys = ON", "PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000"} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure sqlite: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS oauth_schema_version (version INTEGER NOT NULL);
INSERT INTO oauth_schema_version(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM oauth_schema_version);
CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, payload BLOB NOT NULL, created_at TEXT NOT NULL, last_used_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_authorizations (digest BLOB PRIMARY KEY, payload BLOB NOT NULL, consumed_at TEXT);
CREATE TABLE IF NOT EXISTS oauth_consents (digest BLOB PRIMARY KEY, payload BLOB NOT NULL, consumed_at TEXT);
CREATE TABLE IF NOT EXISTS oauth_codes (digest BLOB PRIMARY KEY, payload BLOB NOT NULL, consumed_at TEXT);
CREATE TABLE IF NOT EXISTS oauth_refresh_grants (digest BLOB PRIMARY KEY, family_id TEXT NOT NULL, generation INTEGER NOT NULL, payload BLOB NOT NULL, consumed_at TEXT, revoked_at TEXT);
CREATE INDEX IF NOT EXISTS oauth_refresh_family_idx ON oauth_refresh_grants(family_id);
CREATE INDEX IF NOT EXISTS oauth_authorizations_expiry_idx ON oauth_authorizations(json_extract(payload, '$.ExpiresAt'));
CREATE INDEX IF NOT EXISTS oauth_consents_expiry_idx ON oauth_consents(json_extract(payload, '$.ExpiresAt'));
CREATE INDEX IF NOT EXISTS oauth_codes_expiry_idx ON oauth_codes(json_extract(payload, '$.ExpiresAt'));
`)
	if err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

func (s *Store[A]) RegisterClient(ctx context.Context, client oauthserver.Client, policy oauthserver.StatePolicy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	now := time.Now().UTC()
	if _, err := pruneTx(ctx, tx, policy, now); err != nil {
		return err
	}
	if _, err := pruneClientsTx(ctx, tx, policy.Registration, now); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM oauth_clients").Scan(&count); err != nil {
		return err
	}
	if count >= policy.Registration.MaxClients {
		return oauthserver.ErrCapacity
	}
	payload, err := json.Marshal(client)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO oauth_clients(id,payload,created_at,last_used_at) VALUES(?,?,?,?)", client.ID, payload, client.CreatedAt.UTC().Format(time.RFC3339Nano), client.LastUsedAt.UTC().Format(time.RFC3339Nano))
	if isConstraint(err) {
		return oauthserver.ErrConflict
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store[A]) GetClient(ctx context.Context, id oauthserver.ClientID) (oauthserver.Client, error) {
	var payload []byte
	var lastUsed string
	err := s.db.QueryRowContext(ctx, "SELECT payload,last_used_at FROM oauth_clients WHERE id=?", id).Scan(&payload, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthserver.Client{}, oauthserver.ErrNotFound
	}
	if err != nil {
		return oauthserver.Client{}, err
	}
	var client oauthserver.Client
	if err := json.Unmarshal(payload, &client); err != nil {
		return oauthserver.Client{}, fmt.Errorf("decode client: %w", err)
	}
	client.LastUsedAt, err = time.Parse(time.RFC3339Nano, lastUsed)
	if err != nil {
		return oauthserver.Client{}, fmt.Errorf("decode client activity: %w", err)
	}
	return client, nil
}
func (s *Store[A]) TouchClient(ctx context.Context, id oauthserver.ClientID, at time.Time) error {
	result, err := s.db.ExecContext(ctx, "UPDATE oauth_clients SET last_used_at=? WHERE id=?", at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return oauthserver.ErrNotFound
	}
	return nil
}
func (s *Store[A]) CreateAuthorization(ctx context.Context, state oauthserver.AuthorizationTransaction, policy oauthserver.StatePolicy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := pruneTx(ctx, tx, policy, time.Now().UTC()); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM oauth_authorizations").Scan(&count); err != nil {
		return err
	}
	if count >= policy.Capacity.MaxAuthorizations {
		return oauthserver.ErrCapacity
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO oauth_authorizations(digest,payload) VALUES(?,?)", digestBytes(state.Token), payload)
	if isConstraint(err) {
		return oauthserver.ErrConflict
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store[A]) GetAuthorization(ctx context.Context, digest oauthserver.CredentialDigest) (oauthserver.AuthorizationTransaction, error) {
	var payload []byte
	var consumed sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT payload,consumed_at FROM oauth_authorizations WHERE digest=?", digest[:]).Scan(&payload, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthserver.AuthorizationTransaction{}, oauthserver.ErrNotFound
	}
	if err != nil {
		return oauthserver.AuthorizationTransaction{}, err
	}
	var state oauthserver.AuthorizationTransaction
	if err := json.Unmarshal(payload, &state); err != nil {
		return state, err
	}
	if consumed.Valid {
		state.ConsumedAt, _ = time.Parse(time.RFC3339Nano, consumed.String)
	}
	return state, nil
}
func (s *Store[A]) CommitLogin(ctx context.Context, commit oauthserver.LoginCommit[A], policy oauthserver.StatePolicy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := pruneTx(ctx, tx, policy, time.Now().UTC()); err != nil {
		return err
	}
	var consumed sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT consumed_at FROM oauth_authorizations WHERE digest=?", commit.TransactionDigest[:]).Scan(&consumed); errors.Is(err, sql.ErrNoRows) {
		return oauthserver.ErrNotFound
	} else if err != nil {
		return err
	}
	if consumed.Valid {
		return oauthserver.ErrConsumed
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM oauth_consents").Scan(&count); err != nil {
		return err
	}
	if count >= policy.Capacity.MaxConsents {
		return oauthserver.ErrCapacity
	}
	principal, err := encodePrincipal(s.codec, commit.Consent.Principal)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(consentEnvelope[A]{Session: commit.Consent, Principal: principal})
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_consents(digest,payload) VALUES(?,?)", digestBytes(commit.Consent.Token), payload); isConstraint(err) {
		return oauthserver.ErrConflict
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_authorizations SET consumed_at=? WHERE digest=? AND consumed_at IS NULL", now, commit.TransactionDigest[:]); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store[A]) GetConsent(ctx context.Context, digest oauthserver.CredentialDigest) (oauthserver.ConsentSession[A], error) {
	var payload []byte
	var consumed sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT payload,consumed_at FROM oauth_consents WHERE digest=?", digest[:]).Scan(&payload, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthserver.ConsentSession[A]{}, oauthserver.ErrNotFound
	}
	if err != nil {
		return oauthserver.ConsentSession[A]{}, err
	}
	var envelope consentEnvelope[A]
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return envelope.Session, err
	}
	principal, err := s.codec.DecodePrincipal(envelope.Principal)
	if err != nil {
		return envelope.Session, err
	}
	envelope.Session.Principal = principal
	if consumed.Valid {
		envelope.Session.ConsumedAt, _ = time.Parse(time.RFC3339Nano, consumed.String)
	}
	return envelope.Session, nil
}
func (s *Store[A]) CommitConsent(ctx context.Context, commit oauthserver.ConsentCommit[A], policy oauthserver.StatePolicy) (oauthserver.ConsentCommitResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oauthserver.ConsentCommitResult{}, err
	}
	defer rollback(tx)
	if _, err := pruneTx(ctx, tx, policy, time.Now().UTC()); err != nil {
		return oauthserver.ConsentCommitResult{}, err
	}
	var payload []byte
	var consumed sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT payload,consumed_at FROM oauth_consents WHERE digest=?", commit.ConsentDigest[:]).Scan(&payload, &consumed); errors.Is(err, sql.ErrNoRows) {
		return oauthserver.ConsentCommitResult{}, oauthserver.ErrNotFound
	} else if err != nil {
		return oauthserver.ConsentCommitResult{}, err
	}
	if consumed.Valid {
		return oauthserver.ConsentCommitResult{}, oauthserver.ErrConsumed
	}
	if commit.Decision == oauthserver.ConsentDecisionApprove {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM oauth_codes").Scan(&count); err != nil {
			return oauthserver.ConsentCommitResult{}, err
		}
		if count >= policy.Capacity.MaxCodes {
			return oauthserver.ConsentCommitResult{}, oauthserver.ErrCapacity
		}
		principal, err := encodePrincipal(s.codec, commit.Code.Principal)
		if err != nil {
			return oauthserver.ConsentCommitResult{}, err
		}
		codePayload, err := json.Marshal(codeEnvelope[A]{Record: commit.Code, Principal: principal})
		if err != nil {
			return oauthserver.ConsentCommitResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_codes(digest,payload) VALUES(?,?)", commit.Code.Digest[:], codePayload); isConstraint(err) {
			return oauthserver.ConsentCommitResult{}, oauthserver.ErrConflict
		} else if err != nil {
			return oauthserver.ConsentCommitResult{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_consents SET consumed_at=? WHERE digest=? AND consumed_at IS NULL", time.Now().UTC().Format(time.RFC3339Nano), commit.ConsentDigest[:]); err != nil {
		return oauthserver.ConsentCommitResult{}, err
	}
	return oauthserver.ConsentCommitResult{RedirectURI: ""}, tx.Commit()
}
func (s *Store[A]) GetCodeForExchange(ctx context.Context, binding oauthserver.CodeExchangeBinding) (oauthserver.AuthorizationCodeRecord[A], error) {
	var payload []byte
	var consumed sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT payload,consumed_at FROM oauth_codes WHERE digest=?", binding.Digest[:]).Scan(&payload, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthserver.AuthorizationCodeRecord[A]{}, oauthserver.ErrNotFound
	}
	if err != nil {
		return oauthserver.AuthorizationCodeRecord[A]{}, err
	}
	var envelope codeEnvelope[A]
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return envelope.Record, err
	}
	if envelope.Record.ClientID != binding.ClientID || envelope.Record.RedirectURI != binding.RedirectURI {
		return envelope.Record, oauthserver.ErrBinding
	}
	envelope.Record.Principal, err = s.codec.DecodePrincipal(envelope.Principal)
	if err != nil {
		return envelope.Record, err
	}
	if consumed.Valid {
		envelope.Record.ConsumedAt, _ = time.Parse(time.RFC3339Nano, consumed.String)
	}
	return envelope.Record, nil
}
func (s *Store[A]) CommitCodeExchange(ctx context.Context, commit oauthserver.CodeExchangeCommit[A], policy oauthserver.StatePolicy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := pruneTx(ctx, tx, policy, time.Now().UTC()); err != nil {
		return err
	}
	var consumed sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT consumed_at FROM oauth_codes WHERE digest=?", commit.CodeDigest[:]).Scan(&consumed); errors.Is(err, sql.ErrNoRows) {
		return oauthserver.ErrNotFound
	} else if err != nil {
		return err
	}
	if consumed.Valid {
		return oauthserver.ErrConsumed
	}
	if commit.Refresh == nil {
		return oauthserver.ErrInvalid
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM oauth_refresh_grants").Scan(&count); err != nil {
		return err
	}
	if count >= policy.Capacity.MaxRefreshGrants {
		return oauthserver.ErrCapacity
	}
	principal, err := encodePrincipal(s.codec, commit.Refresh.Principal)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(refreshEnvelope[A]{Grant: *commit.Refresh, Principal: principal})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_refresh_grants(digest,family_id,generation,payload) VALUES(?,?,?,?)", commit.Refresh.Digest[:], commit.Refresh.FamilyID, commit.Refresh.Generation, payload); isConstraint(err) {
		return oauthserver.ErrConflict
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_codes SET consumed_at=? WHERE digest=? AND consumed_at IS NULL", time.Now().UTC().Format(time.RFC3339Nano), commit.CodeDigest[:]); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store[A]) GetRefreshGrant(ctx context.Context, digest oauthserver.CredentialDigest) (oauthserver.RefreshGrant[A], error) {
	var payload []byte
	var consumed, revoked sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT payload,consumed_at,revoked_at FROM oauth_refresh_grants WHERE digest=?", digest[:]).Scan(&payload, &consumed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthserver.RefreshGrant[A]{}, oauthserver.ErrNotFound
	}
	if err != nil {
		return oauthserver.RefreshGrant[A]{}, err
	}
	var envelope refreshEnvelope[A]
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return envelope.Grant, err
	}
	grant, err := s.decodeRefresh(envelope)
	if err != nil {
		return grant, err
	}
	if consumed.Valid {
		grant.ConsumedAt, _ = time.Parse(time.RFC3339Nano, consumed.String)
	}
	if revoked.Valid {
		grant.RevokedAt, _ = time.Parse(time.RFC3339Nano, revoked.String)
	}
	return grant, nil
}
func (s *Store[A]) decodeRefresh(envelope refreshEnvelope[A]) (oauthserver.RefreshGrant[A], error) {
	grant := envelope.Grant
	principal, err := s.codec.DecodePrincipal(envelope.Principal)
	grant.Principal = principal
	return grant, err
}
func (s *Store[A]) CommitRefreshRotation(ctx context.Context, rotation oauthserver.RefreshRotation[A], policy oauthserver.StatePolicy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := pruneTx(ctx, tx, policy, time.Now().UTC()); err != nil {
		return err
	}
	var family string
	var generation uint64
	var consumed, revoked sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT family_id,generation,consumed_at,revoked_at FROM oauth_refresh_grants WHERE digest=?", rotation.CurrentDigest[:]).Scan(&family, &generation, &consumed, &revoked); errors.Is(err, sql.ErrNoRows) {
		return oauthserver.ErrNotFound
	} else if err != nil {
		return err
	}
	if family != string(rotation.FamilyID) || generation != rotation.Generation {
		return oauthserver.ErrBinding
	}
	if consumed.Valid || revoked.Valid {
		if err := revokeFamilyTx(ctx, tx, rotation.FamilyID, time.Now().UTC()); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return oauthserver.ErrRevoked
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM oauth_refresh_grants").Scan(&count); err != nil {
		return err
	}
	if count >= policy.Capacity.MaxRefreshGrants {
		return oauthserver.ErrCapacity
	}
	principal, err := encodePrincipal(s.codec, rotation.Successor.Principal)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(refreshEnvelope[A]{Grant: rotation.Successor, Principal: principal})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_refresh_grants(digest,family_id,generation,payload) VALUES(?,?,?,?)", rotation.Successor.Digest[:], rotation.Successor.FamilyID, rotation.Successor.Generation, payload); isConstraint(err) {
		return oauthserver.ErrConflict
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE oauth_refresh_grants SET consumed_at=? WHERE digest=? AND consumed_at IS NULL", time.Now().UTC().Format(time.RFC3339Nano), rotation.CurrentDigest[:]); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store[A]) RevokeRefreshFamily(ctx context.Context, family oauthserver.RefreshFamilyID, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := revokeFamilyTx(ctx, tx, family, at); err != nil {
		return err
	}
	return tx.Commit()
}
func revokeFamilyTx(ctx context.Context, tx *sql.Tx, family oauthserver.RefreshFamilyID, at time.Time) error {
	_, err := tx.ExecContext(ctx, "UPDATE oauth_refresh_grants SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL", at.UTC().Format(time.RFC3339Nano), family)
	return err
}
func (s *Store[A]) Prune(ctx context.Context, policy oauthserver.StatePolicy) (oauthserver.PruneStats, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oauthserver.PruneStats{}, err
	}
	defer rollback(tx)
	stats, err := pruneTx(ctx, tx, policy, time.Now().UTC())
	if err != nil {
		return stats, err
	}
	if err := tx.Commit(); err != nil {
		return stats, err
	}
	return stats, nil
}

func pruneTx(ctx context.Context, tx *sql.Tx, _ oauthserver.StatePolicy, now time.Time) (oauthserver.PruneStats, error) {
	var stats oauthserver.PruneStats
	cutoff := now.UTC().Format(time.RFC3339Nano)
	for _, item := range []struct {
		query  string
		target *int
	}{
		{"DELETE FROM oauth_authorizations WHERE json_extract(payload, '$.ExpiresAt') <= ?", &stats.Authorizations},
		{"DELETE FROM oauth_consents WHERE json_extract(payload, '$.ExpiresAt') <= ?", &stats.Consents},
		{"DELETE FROM oauth_codes WHERE json_extract(payload, '$.ExpiresAt') <= ?", &stats.Codes},
	} {
		result, err := tx.ExecContext(ctx, item.query, cutoff)
		if err != nil {
			return stats, err
		}
		removed, err := result.RowsAffected()
		if err != nil {
			return stats, err
		}
		*item.target = int(removed)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM oauth_refresh_grants
WHERE family_id IN (
  SELECT family_id FROM oauth_refresh_grants
  GROUP BY family_id
  HAVING MAX(json_extract(payload, '$.ExpiresAt')) <= ?
)`, cutoff)
	if err != nil {
		return stats, err
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return stats, err
	}
	stats.RefreshGrants = int(removed)
	return stats, nil
}
func pruneClientsTx(ctx context.Context, tx *sql.Tx, policy oauthserver.RegistrationPolicy, now time.Time) (int, error) {
	cutoff := now.Add(-policy.UnverifiedClientTTL).UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `DELETE FROM oauth_clients
WHERE last_used_at <= ?
  AND json_extract(payload, '$.Trust') = ?
  AND id NOT IN (
    SELECT json_extract(payload, '$.ClientID')
    FROM oauth_authorizations
    WHERE consumed_at IS NULL AND json_extract(payload, '$.ExpiresAt') > ?
  )`, cutoff, oauthserver.ClientTrustUnverified, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	return int(removed), err
}

func (s *Store[A]) Counts(ctx context.Context) (oauthserver.StateCounts, error) {
	var counts oauthserver.StateCounts
	for _, item := range []struct {
		name   string
		target *int
	}{{"oauth_clients", &counts.Clients}, {"oauth_authorizations", &counts.Authorizations}, {"oauth_consents", &counts.Consents}, {"oauth_codes", &counts.Codes}, {"oauth_refresh_grants", &counts.RefreshGrants}} {
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+item.name).Scan(item.target); err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// Envelopes keep application principal serialization behind PrincipalCodec.
type consentEnvelope[A any] struct {
	Session   oauthserver.ConsentSession[A] `json:"session"`
	Principal []byte                        `json:"principal"`
}
type codeEnvelope[A any] struct {
	Record    oauthserver.AuthorizationCodeRecord[A] `json:"record"`
	Principal []byte                                 `json:"principal"`
}
type refreshEnvelope[A any] struct {
	Grant     oauthserver.RefreshGrant[A] `json:"grant"`
	Principal []byte                      `json:"principal"`
}

func encodePrincipal[A any](codec oauthserver.PrincipalCodec[A], principal oauthserver.Principal[A]) ([]byte, error) {
	return codec.EncodePrincipal(principal)
}
func digestBytes[T ~string](value T) []byte {
	digest := oauthserver.DigestCredential(string(value))
	return digest[:]
}
func rollback(tx *sql.Tx) { _ = tx.Rollback() }
func isConstraint(err error) bool {
	return err != nil && (!errors.Is(err, context.Canceled)) && (contains(err.Error(), "UNIQUE constraint") || contains(err.Error(), "constraint failed"))
}
func contains(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return true
		}
	}
	return false
}

var _ oauthserver.Store[struct{}] = (*Store[struct{}])(nil)
