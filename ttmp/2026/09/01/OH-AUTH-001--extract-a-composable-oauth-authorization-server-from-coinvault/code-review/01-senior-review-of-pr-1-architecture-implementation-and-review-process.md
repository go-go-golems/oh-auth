---
Title: Senior Review of PR 1 Architecture Implementation and Review Process
Ticket: OH-AUTH-001
Status: active
Topics:
    - oauth
    - security
    - architecture
    - golang
    - library
DocType: code-review
Intent: long-term
Owners: []
RelatedFiles:
    - Path: repo://pkg/httptransport/server.go
      Note: Protocol boundary and routing evidence
    - Path: repo://pkg/jwttokens/service.go
      Note: Fixed-trust token adapter evidence
    - Path: repo://pkg/oauthserver/engine.go
      Note: Core transition and revocation evidence
    - Path: repo://pkg/oauthserver/ports.go
      Note: Store and capability contract evidence
    - Path: repo://pkg/sqlitestore/store.go
      Note: Durability lifecycle and raw-payload evidence
    - Path: ws://coinvault/internal/mcpoauth/provider.go
      Note: Consumer composition and policy adapter evidence
ExternalSources:
    - https://github.com/go-go-golems/oh-auth/pull/1
Summary: 'Evidence-backed senior review of every PR #1 finding, the current oh-auth and CoinVault implementation, systemic causes, merge blockers, and a staged remediation architecture.'
LastUpdated: 2026-09-01T20:05:00-04:00
WhatFor: Orient a new engineer, correct the prior green-review claim, and define the work required before oh-auth can be merged or released.
WhenToUse: 'Read before changing PR #1, implementing its remaining fixes, reviewing OAuth state transitions, or declaring OH-AUTH-001 release-ready.'
---


# Senior Review of PR 1 Architecture Implementation and Review Process

## 1. Executive summary

PR #1 has a promising architectural center: a protocol-neutral generic engine, narrow application policy ports, exact resource audiences, mandatory PKCE S256, canonical scope sets, fixed-trust JWT verification, and transactional SQLite operations. Those choices are worth preserving. The package dependency direction is also good: `pkg/oauthserver` does not import HTTP, SQLite, JWT, CoinVault, MCP, or RAG code.

The branch is **not ready to merge or release**. The final Codex review on head commit `6cf0ff2` produced four findings that remain applicable:

1. unauthenticated dynamic registration can permanently exhaust the client table;
2. refresh ineligibility ignores a failed durable family revocation;
3. issuer paths are advertised but not consistently mounted or used by consent;
4. registration returns a `Location` for a resource that does not exist.

The local senior review found additional issues that are at least as important:

- SQLite persists raw authorization-transaction and consent credentials inside JSON payloads even though the README and design promise digest-only durable storage.
- Store commit methods do not authoritatively verify that successor state is derived from the consumed predecessor; the engine currently supplies correct values, but the atomic boundary does not enforce the advertised invariant.
- explicit revocation hides all store lookup failures as successful RFC 7009 responses, so a database failure can leave an active token while returning `200 OK`;
- unknown numeric `RevalidationStatus` values are treated as eligible when the returned subject matches, rather than failing closed;
- configuration is duplicated across engine, HTTP transport, token service, and resource registry, allowing issuer, policy, resource, and clock split-brain;
- SQLite and `memorytest` use wall-clock time directly instead of the engine's injected clock, and their pruning semantics differ;
- retention settings, `TouchClient`, `NewTokenID`, and most of the audit port are unused or only partially wired;
- the conformance, failure-injection, fuzz, concurrency, and complete HTTP-flow suites required by the design do not exist.

The prior session conclusion that “the latest Codex re-review produced no inline findings” was incorrect. It observed an earlier review/check state before the review of `6cf0ff2` completed. The GitHub evidence snapshot contains 15 comments: five on `d2c03e8`, five on `eea2048`, one CodeQL annotation on `6df26ff`, and four on `6cf0ff2`. This report corrects the ticket record and treats asynchronous review completion as a process issue.

### Merge recommendation

**Do not merge PR #1 as-is.** Complete the P1/P2 pre-merge remediation in Section 18, add the minimum conformance and fault-injection tests in Section 19, rerun review against the exact head commit, and only then reconsider merge readiness.

## 2. Scope, evidence, and method

This review covers:

- all inline comments on [oh-auth PR #1](https://github.com/go-go-golems/oh-auth/pull/1), including older/outdated comments;
- every current package under `oh-auth/pkg`;
- current tests, CI workflows, README, Makefile, design, diary, and branch history;
- the consuming CoinVault adapter in `coinvault/internal/mcpoauth/provider.go`;
- the CoinVault composition root in `coinvault/cmd/coinvault/cmds/mcp.go`;
- implementation commits from `523eeea` through `6cf0ff2`;
- the difference between the design contract and executable evidence.

Evidence artifacts:

- `sources/github/pr-1-review-comments.json` is the full REST snapshot of PR inline comments.
- `sources/github/README.md` records capture scope and commit counts.
- `scripts/02-capture-pr-review.sh` refreshes the snapshot.
- `scripts/03-probe-sqlite-boundaries.sh` demonstrates raw credential persistence and stale client activity reads without modifying production code.
- `reference/01-investigation-diary.md` records the original implementation and review sequence.

Local validation used `GOWORK=off`. At review time, ordinary tests passed, but that is evidence of regression-free execution only—not evidence that protocol and failure semantics are complete.

## 3. Verdict at a glance

### 3.1 What is strong

- **Dependency direction:** `oauthserver` is standard-library-only and independent of consumers.
- **Typed application identity:** `Principal[A]` keeps application attributes typed while standard identity fields remain fixed.
- **Monotonic scopes:** `ScopeSet` is canonical, copy-on-read, and supports explicit intersection.
- **Exact resource binding:** JWT verification requires one exact audience and rejects cross-resource use.
- **Mandatory PKCE:** only S256 is accepted; verifier syntax and challenge verification are explicit.
- **Fixed JWT trust:** RS256 and configured key IDs are selected locally; token-provided trust material is rejected.
- **Transition vocabulary:** methods such as `CommitCodeExchange` and `CommitRefreshRotation` express protocol transitions better than generic CRUD.
- **Refresh replay side effect:** SQLite commits family revocation before returning `ErrRevoked` on consumed-token replay.
- **Review responsiveness:** the first ten Codex findings received targeted code and regression tests.

### 3.2 What blocks merge

- **P1:** permanent unauthenticated client-registration exhaustion.
- **P1:** failed ineligibility revocation is ignored.
- **P1:** raw transaction and consent credentials are durably persisted.
- **P1:** store commits do not enforce predecessor-to-successor authority constraints.
- **P1:** explicit revocation hides infrastructure failure and can falsely report success.
- **P2:** issuer path support is internally inconsistent across metadata, route mounting, callback, consent redirect, and form action.
- **P2:** registration advertises a nonexistent management URL.
- **P2:** malformed revalidation enum values can pass as eligible.
- **P2:** runtime configuration can become split-brain.
- **P2:** deterministic clock and retention contracts are not implemented consistently.

### 3.3 What should follow before release

- shared memory/SQLite store conformance;
- complete HTTP authorization-code, consent, token, refresh, and revoke flows;
- fault-injection tests for every side-effecting dependency;
- parameter-pollution and query-boundary tests;
- migration/version checks and explicit expiry columns;
- complete audit event coverage;
- independent RAG consumer and audience-isolation integration;
- final smoke only after all deterministic gates pass.

## 4. OAuth concepts an intern needs first

OAuth separates four roles:

- **Resource owner:** the employee deciding whether a client receives access.
- **Client:** Claude, ChatGPT, or another application requesting a grant.
- **Authorization server:** oh-auth plus application adapters; authenticates the employee, gathers consent, and issues tokens.
- **Resource server:** CoinVault MCP or a future RAG API; validates an access token and enforces scopes.

A **resource** is the exact API audience, such as `https://mcp.example.test/mcp`. A **scope** is a named permission within that resource. A token for MCP must not work at RAG even if the same employee and client are involved.

PKCE protects the authorization code. The client generates a verifier, sends only its S256 challenge during authorization, and proves possession of the verifier during code exchange. The authorization code is short-lived and one-time. A refresh token lasts longer, rotates on use, and belongs to a family so replay of an older generation can revoke the whole family.

The intended browser and back-channel flow is:

```text
Client                    Authorization Server                 Identity Provider
  | GET /authorize               |                                      |
  | client, redirect, state,     |                                      |
  | scope, resource, PKCE ------>| validate exact bindings              |
  |                              | create transaction                    |
  |<-----------------------------| redirect to employee login ---------->|
  |                              |<------ authenticated principal -------|
  |                              | consume transaction                   |
  |                              | create one-time consent session       |
  |<-----------------------------| render consent                        |
  | POST decision + scopes ----->| consume consent                       |
  |<-----------------------------| redirect code + original state        |
  | POST /token code+verifier -->| verify PKCE and bindings              |
  |                              | atomically code -> refresh family     |
  |<-----------------------------| access token + refresh token          |
```

The resource request is deliberately separate:

```text
Client                    MCP resource server                 JWT verifier
  | Authorization: Bearer ... -->|                                |
  |                               | verify signature, issuer,      |
  |                               | exact MCP audience, time ------>|
  |                               |<--------- VerifiedAccessToken   |
  |                               | enforce operation scopes        |
  |<------------------------------| result or denial                |
```

## 5. Current package architecture

```text
                    application composition root
                              |
             +----------------+----------------+
             |                                 |
      identity/policy adapters          resource integration
             |                                 |
             v                                 v
      +---------------+                 +---------------+
      | httptransport |                 | oauthresource |
      +-------+-------+                 +-------+-------+
              |                                 |
              v                                 |
      +---------------+ <-----------------------+
      | oauthserver   |  domain types and ports
      +---+-------+---+
          |       |
          v       v
  +-----------+ +-----------+
  |sqlitestore| | jwttokens |
  +-----------+ +-----------+

  memorytest implements ports for deterministic tests.
```

### 5.1 `pkg/oauthserver`

This is the domain core:

- `identifiers.go` validates IDs, exact URLs, opaque credentials, and PKCE.
- `scopes.go` implements canonical immutable scope sets.
- `model.go` defines principals, clients, transaction state, consent, codes, refresh grants, and token results.
- `ports.go` defines store, resource, scope-policy, identity-revalidation, token, secret, clock, login, and audit capabilities.
- `engine.go` orchestrates transitions.
- `config.go` owns TTLs, capacities, HTTP limits, issuer/resource validation, and defaults.

The core's separation from HTTP and persistence is sound. The important caveat is that the store and engine currently share responsibility for invariants without a precise division. That ambiguity is the source of several systemic findings.

### 5.2 `pkg/httptransport`

`server.go` maps OAuth HTTP requests to engine inputs. It owns:

- discovery metadata and JWKS;
- dynamic client registration;
- authorization initiation;
- consent GET/POST;
- token and revocation endpoints;
- identity callback completion;
- form/JSON limits and browser headers.

The file is only 388 lines, but it contains almost every external protocol boundary. Current direct package coverage is 38.5%, and consent, revocation, JWKS, and identity-callback handlers have 0% direct statement coverage.

### 5.3 `pkg/sqlitestore`

`store.go` owns schema creation and all durable transitions. It serializes records as JSON payloads while keeping selected timestamps and family metadata in columns. It uses one database connection and transactions for transitions.

The implementation currently mixes three representations:

- digest/identity columns used for lookup and atomic checks;
- JSON payloads containing domain records;
- duplicated timestamp columns and timestamp values inside payloads.

That mixture enabled fast implementation but causes stale data, raw-secret persistence, weak migration semantics, and fragile JSON-based expiry pruning.

### 5.4 `pkg/jwttokens`

`service.go` signs and verifies RS256 access tokens. It has the strongest focused tests and 79% direct statement coverage. It correctly rejects wrong audience, reserved-claim collisions, unknown keys, wrong type/algorithm, and token-selected trust headers.

Residual issues include configuration duplication, no library-level RSA strength check, and an unused `SecretSource.NewTokenID` contract because the JWT adapter generates JTIs directly.

### 5.5 `pkg/oauthresource`

This package extracts bearer tokens, delegates verification, formats challenges, and renders resource metadata. It has no tests and 0% direct coverage. It is small, but resource metadata and challenge formatting are protocol-visible and should still have table tests.

### 5.6 `pkg/memorytest`

This package is intended to be a deterministic executable contract. It is useful for engine tests, but it is not conformant with SQLite:

- it uses `time.Now()` directly;
- it does not prune on admission;
- it prunes only consumed authorization/consent/code state;
- it does not prune refresh families;
- it retains raw credentials in in-memory records;
- it cannot inject store failures;
- no shared suite is run against both stores.

An intern should therefore treat it as a convenient fake, not as an authoritative store specification.

### 5.7 CoinVault consumer

`coinvault/internal/mcpoauth/provider.go` supplies GEC identity, scope, claim, login, and revalidation adapters. It correctly validates RSA strength, binds the exact resource, copies capability slices, and maps verified tokens into `embeddable.AuthPrincipal`.

However, CoinVault still combines authorization-server route mounting and resource-server verification in one `HTTPAuthProvider`. The design explicitly wanted authorization-server routes mounted by the application composition root and a smaller verifier/metadata adapter for MCP. The cutover removed duplicate mechanics but did not complete that ownership separation.

CoinVault has only one shallow provider integration test. It checks construction, invalid-token rejection, resource metadata, and discovery status; it does not run registration, authorization, callback, consent, code exchange, refresh, revoke, or wrong-audience flows.

## 6. State machine and authority boundaries

The engine is easiest to understand as one-time state transitions:

```text
AuthorizationTransaction --CompleteLogin--> ConsentSession
ConsentSession --approve---------------> AuthorizationCodeRecord
ConsentSession --deny------------------> terminal denial
AuthorizationCodeRecord --ExchangeCode--> RefreshGrant generation 0
RefreshGrant generation n --Refresh----> generation n+1
RefreshGrant family --Revoke/replay-----> revoked family
```

Every arrow has three kinds of invariants:

1. **Binding invariants** — same client, redirect, resource, PKCE challenge, and subject where applicable.
2. **Authority invariants** — successor scopes are a subset of every previous and current authority boundary.
3. **lifecycle invariants** — predecessor exists, is unexpired, unconsumed, and unrevoked; only one concurrent transition wins.

The design says the store commit is authoritative because reads are advisory. Current SQLite commits mostly enforce lifecycle uniqueness but not complete binding or authority derivation. For example:

- `CommitLogin` checks only that the transaction digest exists and is unconsumed, then inserts the supplied consent.
- `CommitConsent` checks the consent digest and consumed flag, then inserts the supplied code.
- `CommitCodeExchange` checks the code digest and consumed flag, then inserts the supplied refresh grant.
- `CommitRefreshRotation` checks family and generation, but not that the successor retains client, subject, resource, expiry, family, generation increment, or narrowed scopes.

The engine currently constructs correct successors, so ordinary tests pass. The architectural problem is that the persistence boundary cannot detect an engine bug, adapter misuse, or future refactor that expands authority.

## 7. PR review chronology and current disposition

The source of truth for comment text is `sources/github/pr-1-review-comments.json`.

### 7.1 Round 1: reviewed commit `d2c03e8`

| ID | Priority | Finding | Current disposition |
|---|---:|---|---|
| [3907215835](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907215835) | P1 | RFC-compatible dynamic-registration request/response fields | Fixed narrowly in `httptransport.register`; metadata arrays remain under-validated. |
| [3907215845](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907215845) | P1 | Prune expired transient state before capacity checks | Original case fixed for SQLite; client lifecycle, retention, clocks, and memory-store conformance remain systemic gaps. |
| [3907215856](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907215856) | P1 | Derive endpoints from configured issuer | Host poisoning/proxy bug fixed; issuer-path route ownership remains incomplete. |
| [3907215862](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907215862) | P2 | Preserve arbitrary principal codec bytes | Fixed using `[]byte` envelopes and a non-JSON codec test. |
| [3907215872](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907215872) | P2 | Apply body/form limits before parsing | Original body-bound case fixed; duplicate scalar parameters, query bounds, media-type parsing, and JSON arrays remain. |

### 7.2 Round 2: reviewed commit `eea2048`

| ID | Priority | Finding | Current disposition |
|---|---:|---|---|
| [3907446467](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907446467) | P1 | Bind eligible revalidation output to original subject | Fixed for empty/different subjects; invalid enum values still fail open. |
| [3907446479](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907446479) | P2 | Redirect trusted authorization errors with state | Fixed for `BeginAuthorization` errors; later login-starter failures still return JSON after redirect trust is known. |
| [3907446487](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907446487) | P2 | Validate all operational limits | Positive-value checks added; some accepted settings are unused or duplicated. |
| [3907446493](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907446493) | P2 | Allow query components in exact redirect URIs | Fixed by separating origin and redirect validators. |
| [3907446498](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907446498) | P2 | Recognize IPv6 loopback without brackets | Fixed and regression-tested. |

### 7.3 CodeQL annotation: commit `6df26ff`

| ID | Finding | Current disposition |
|---|---|---|
| [3907519639](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907519639) | User-controlled open redirect | No obvious open redirect after exact registered-client lookup, but trust is not represented by a distinct type and the thread remains unresolved. Treat as a trust-model design concern, not merely a suppression candidate. |

### 7.4 Round 3: reviewed head `6cf0ff2`

| ID | Priority | Finding | Current disposition |
|---|---:|---|---|
| [3907604521](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907604521) | P1 | Make dynamic-client capacity recoverable | **Unresolved and merge-blocking.** |
| [3907604555](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907604555) | P1 | Propagate refresh-family revocation failures | **Unresolved and merge-blocking.** |
| [3907604565](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907604565) | P2 | Resolve consent URLs against issuer/mount prefix | **Unresolved; part of a larger path-support inconsistency.** |
| [3907604576](https://github.com/go-go-golems/oh-auth/pull/1#discussion_r3907604576) | P2 | Remove dangling registration `Location` | **Unresolved; remove it unless management is implemented.** |

## 8. Detailed assessment of the older fixed findings

### 8.1 RFC dynamic registration

The original HTTP adapter decoded directly into an engine struct with no JSON tags and returned a Go-domain client object. The fix correctly introduced wire DTO fields such as `client_name`, `redirect_uris`, `scope`, and `client_id` around the engine model (`pkg/httptransport/server.go:103-131`). This is the right architecture: wire representations should not leak into the domain API.

Residual concerns:

- `grant_types` and `response_types` are decoded but ignored;
- unsupported requested combinations are silently replaced by the server's fixed response;
- JSON arrays do not use `MaxArrayLength`;
- the response is assembled as `map[string]any` rather than a typed DTO;
- the dangling `Location` creates a new interoperability defect.

The systemic lesson is to define a complete protocol adapter contract, not only enough tags to satisfy one fixture.

### 8.2 Expiry pruning before admission

The fix moved expiry pruning into the same SQLite transaction as admission. That directly resolves abandoned transient rows permanently exhausting authorizations, consents, codes, and refresh grants.

The implementation still does not match the full lifecycle design:

- `pruneTx` ignores its `StatePolicy` argument (`pkg/sqlitestore/store.go:485`);
- `ConsumedState` and `RevokedState` are not applied by SQLite;
- client rows are never pruned;
- memory and SQLite prune different categories;
- expiry is extracted from JSON text instead of a typed indexed column;
- every admission uses `time.Now()` rather than an injected clock.

This is why the third review found the next quota issue immediately after the first quota fix.

### 8.3 Issuer-derived endpoint URLs

Replacing request-derived scheme/Host values with the configured issuer fixed reverse-proxy breakage and Host-header poisoning. That was a necessary security fix.

The helper `absolute(path)` is string concatenation, while `Mount` uses hardcoded root paths. If issuer is `https://auth.example/base`, metadata advertises `https://auth.example/base/oauth/token`, but the mux still mounts `/oauth/token`. The system therefore claims path support that it does not implement.

The correct choice is either:

- constrain v0.1 issuer to an origin with no path; or
- parse one endpoint set, mount its path prefix, use it for callbacks, consent links/forms, metadata, and well-known rules.

Half-support is worse than an explicit restriction.

### 8.4 Opaque principal codec bytes

The change from `json.RawMessage` to `[]byte` is correct. JSON base64-encodes arbitrary bytes, preserving the `PrincipalCodec` contract. `codec_test.go` provides a focused regression.

A future schema should still record a codec/version identifier so consumers can migrate encoded principals deliberately. The design called for one, but the schema does not contain it.

### 8.5 HTTP form bounds

Wrapping the body in `http.MaxBytesReader` before `ParseForm` correctly enforces the configured body limit. Field and selected array bounds are also useful.

Remaining boundary issues:

- exact string comparison rejects valid media types with parameters;
- JSON uses `HasPrefix("application/json")`, which can accept invalid lookalikes;
- `r.Form` combines body and query parameters;
- scalar duplicates are accepted and `Get` silently selects one;
- authorization query size and repeated parameters are not bounded;
- registration JSON arrays are bounded only by total bytes, not `MaxArrayLength`.

Use `mime.ParseMediaType`, validate the expected parameter set, and reject duplicates for scalar OAuth parameters.

## 9. Detailed assessment of the second review round

### 9.1 Subject-bound revalidation

The added equality check prevents a cache or adapter lookup error from moving a refresh grant between accounts. This was a critical correction.

The code should use an exhaustive switch:

```go
switch result.Status {
case RevalidationEligible:
    require result.Principal.Subject == grant.Principal.Subject
case RevalidationIneligible:
    durably revoke family; return invalid_grant
case RevalidationUnknown:
    return temporarily_unavailable
default:
    return temporarily_unavailable // fail closed
}
```

Current code handles only `Unknown` and `Ineligible`, then treats all other values as eligible if the subject matches. Go enums are integers; adapters can return out-of-range values.

### 9.2 Trusted authorization error redirects

The engine now validates client ID plus exact registered redirect before the transport adds `error`, `error_description`, and original `state`. That is correct for failures such as invalid resource or scope after redirect trust is established.

The type `RedirectURI` means only “syntactically valid URL,” not “registered redirect for this client.” Returning the same type from `ValidateRedirect` hides a security distinction from both reviewers and CodeQL. A private or capability-style `TrustedRedirect` should be produced only by exact lookup, or the engine should return the final error redirect itself.

The flow also remains inconsistent after authorization state creation. If `Login` is nil or `AuthorizationURL` fails, the transport returns JSON even though `BeginAuthorizationResult.LoginContext` already contains a trusted redirect and state. Error disposition should be an explicit result of the transition stage, not re-derived ad hoc by each branch.

### 9.3 Complete positive policy validation

The added checks prevent deterministic zero-capacity denial after successful construction. That resolves the exact review finding.

Validation alone does not prove policy effectiveness. `RevokedState` is positive but unused; HTTP policy exists in both engine config and transport config; and the store applies system time independently. Every config field should have:

- one owner;
- one documented unit and semantic;
- at least one behavior test;
- no duplicate independent copy.

### 9.4 Query-bearing and IPv6 loopback redirects

Both fixes are correct. Exact registered-string matching allows a fixed query-bearing callback, and `URL.Hostname()` returns `::1` without brackets. These are good examples of narrow parser regression tests.

They also show why URL parsing needed planned fuzz/table coverage before HTTP integration: URL edge behavior is easy to misremember and static analysis will not establish intended interoperability.

## 10. The four currently unresolved PR findings

### 10.1 P1 — permanent dynamic-registration exhaustion

`/oauth/register` is unauthenticated. SQLite counts all clients and rejects registration at `MaxClients`. No operation deletes or expires clients. `TouchClient` is never called, and even if it were, it updates only a column that `GetClient` does not read.

An attacker needs only 256 valid registrations under defaults to deny every future client. Restarting does not help because the state is durable.

This is not just a missing `DELETE`. Safe lifecycle needs a policy:

- whether DCR is enabled;
- who may attempt it and at what rate;
- whether equivalent metadata is deduplicated;
- when an unverified client expires;
- how active authorization state prevents premature eviction;
- how last use is updated atomically;
- whether a management endpoint exists.

Recommended v0.1 posture:

1. make DCR disabled unless an application supplies an explicit `RegistrationAdmission` policy;
2. add per-source/rate controls in the HTTP composition layer;
3. add an idle lease for unverified clients;
4. prune only clients with no active child state;
5. call `TouchClient` during successful authorization/token activity or replace it with an atomic store transition;
6. test capacity recovery and active-flow preservation.

### 10.2 P1 — ignored refresh-family revocation failure

When revalidation says the subject is ineligible, `engine.Refresh` discards the result of `RevokeRefreshFamily`. If SQLite is unavailable, the engine returns `invalid_grant`, but the token remains active. A later eligible revalidation can refresh it.

Correct pseudocode:

```go
case RevalidationIneligible:
    if err := store.RevokeRefreshFamily(ctx, grant.FamilyID, now); err != nil {
        audit("refresh", "revocation_failed")
        return temporaryError("identity revocation could not be persisted", err)
    }
    audit("refresh", "ineligible_revoked")
    return invalidGrant(ErrRevoked)
```

The rule is: never report a durable security state transition unless persistence confirms it.

### 10.3 P2 — issuer path and consent URL mismatch

`Engine.CompleteLogin` returns a root-relative consent URL. The consent template posts to root-relative `/oauth/consent`. `Server.Mount` mounts all endpoints at the host root. Meanwhile `Config.Validate` accepts issuer paths and metadata uses `issuer + endpoint path`.

This is a system-wide path bug, not only a consent-link bug. It affects:

- advertised metadata endpoints;
- mux route registration;
- identity callback return URL in CoinVault;
- consent redirect;
- consent form action;
- JWKS and registration URLs;
- authorization-server well-known location semantics.

For v0.1, the least risky solution is to reject issuer paths other than empty or `/`. If path-based issuers are a real requirement, introduce a parsed `EndpointSet` and mount prefix as one tested feature.

### 10.4 P2 — dangling registration `Location`

Registration sets `Location: /oauth/register/{client_id}`, but no GET/update/delete route exists. The header tells clients that a management resource exists and guarantees a 404 when followed.

Do not implement a management protocol accidentally to preserve one header. Remove `Location` for v0.1. If RFC 7592 management is later required, design registration access tokens, authentication, rotation, read/update/delete semantics, and lifecycle as a separate feature.

## 11. Additional local finding: raw credentials in durable storage

The README says “OAuth credentials are opaque and stored only as digests by durable stores.” The design says transaction, consent, code, and refresh credentials are digest-only.

Current models include raw fields:

- `AuthorizationTransaction.Token` at `pkg/oauthserver/model.go:58`;
- `ConsentSession.Token` at `pkg/oauthserver/model.go:70`.

SQLite marshals those complete records at `pkg/sqlitestore/store.go:150` and `:211`. The table key is a digest, but the JSON payload still contains the raw credential.

The reproducible probe reports:

```text
touch_visible_through_GetClient=false
oauth_authorizations_contains_raw_credential=True
oauth_consents_contains_raw_credential=True
```

Authorization codes and refresh tokens are represented by digests in their stored models; transaction and consent credentials are not. The test named `TestStoreTransitionsAndDigestOnlyState` never inspects database bytes, so its name overstates coverage.

Recommended representation:

```go
// engine-facing creation result
struct NewAuthorization {
    RawTransaction TransactionToken
    Record StoredAuthorization // no raw secret field
}

// store-facing record
struct StoredAuthorization {
    Digest CredentialDigest
    ClientID ClientID
    ...
}
```

Do the same for consent. Reads by digest should return records without raw secrets. The engine already has the presented raw credential and can calculate its digest; it does not need the store to return plaintext.

This is a merge blocker because it violates an explicit security boundary and makes a database disclosure immediately replayable for all live transaction and consent records.

## 12. Additional local finding: transition commits are not authoritative

The design correctly states: “A prior read is advisory; the commit is authoritative.” The implementation does not fully satisfy that rule.

A safe transition commit must compare predecessor state and successor state inside one transaction. Current commit structs mostly carry only a predecessor digest plus a caller-built successor. The store checks existence/consumption but does not prove derivation.

Required checks include:

```text
CommitLogin:
  successor.client == predecessor.client
  successor.redirect == predecessor.redirect
  successor.state == predecessor.state
  successor.pkce == predecessor.pkce
  successor.resource == predecessor.resource
  successor.allowedScopes subset of predecessor.requestedScopes
  predecessor unexpired and unconsumed

CommitConsent:
  code.client/redirect/state/pkce/resource/principal == consent snapshot
  code.scopes subset of consent.allowedScopes
  code expiry valid

CommitCodeExchange:
  refresh.client/principal/resource/scopes derived exactly from code
  code binding, expiry, PKCE, and unconsumed state authoritative

CommitRefreshRotation:
  successor.family == current.family
  successor.generation == current.generation + 1
  successor.client/subject/resource/expiry unchanged
  successor.scopes subset of current.scopes
  current unexpired, unconsumed, unrevoked
```

There are two viable designs:

1. **Store builds the successor from a small transition command.** Strongest invariant, more codec/business work in the adapter.
2. **Engine builds the successor; store receives expected predecessor bindings and verifies all monotonic fields.** More duplication, but keeps policy in the engine.

Either is better than accepting an arbitrary successor. This is systemic because the library's main safety claim is transition-oriented atomic persistence.

## 13. Additional local finding: revocation can falsely report success

`Engine.Revoke` intentionally hides unknown tokens and client mismatches, as RFC 7009 requires. It currently also hides every store error:

```go
grant, err := store.GetRefreshGrant(...)
if err != nil || grant.ClientID != clientID {
    return nil
}
```

A database timeout, corruption error, or canceled query therefore returns success while leaving a known active token untouched. Non-disclosure does not require swallowing infrastructure failure.

Correct classification:

```go
switch {
case err == nil && grant.ClientID == clientID:
    return store.RevokeRefreshFamily(...)
case err == nil:
    return nil // wrong client: non-disclosing success
case errors.Is(err, ErrNotFound):
    return nil // unknown token: non-disclosing success
default:
    return temporaryError // transport returns 503
}
```

This is the same systemic rule as the ineligible-refresh finding: protocol privacy must not be confused with persistence success.

## 14. Additional local architecture findings

### 14.1 Revalidation enum is not exhaustive

Only `Unknown` and `Ineligible` are matched explicitly. Any future or invalid integer value proceeds as eligible if the subject matches. Use a switch with an explicit `Eligible` case and fail-closed default.

### 14.2 Principal trust boundary lacks validation

`CompleteLogin` accepts a `Principal[A]` and immediately invokes scope policy. It does not require a valid non-empty subject. JWT issuance eventually rejects an empty subject, but by then transaction and consent transitions may have occurred. Validate principal invariants at callback completion before consuming authorization state.

### 14.3 Configuration can split-brain

The same concepts are independently supplied in multiple places:

- issuer in `oauthserver.Config`, `httptransport.Config`, and `jwttokens.Config`;
- resources in `oauthserver.Config`, engine `Dependencies.Resources`, and HTTP `Resources`;
- HTTP policy in engine config and HTTP transport config;
- clock in engine and JWT, while stores ignore both;
- token service in engine and HTTP transport.

Nothing proves they are identical. A consumer can advertise issuer A, sign issuer B, authorize resource registry C, and list metadata registry D.

Create one validated runtime assembly that owns immutable issuer, endpoint set, registry, policy, clock, and token service. Adapters should receive that assembly or typed views from it rather than repeat values.

### 14.4 Clock semantics are split

The engine and JWT service support an injected clock. SQLite and memory stores call `time.Now()` directly for pruning and transition timestamps. A fake-clock test can therefore declare state expired in the engine while the store sees it as live, or vice versa.

The store should be constructed with the same clock, or every transition command should carry an authoritative `Now`. Time should be normalized to UTC at one boundary.

### 14.5 Retention policy is accepted but not implemented

SQLite's `pruneTx` ignores `StatePolicy`; `RevokedState` is unused everywhere; memory applies only `ConsumedState` to three record categories. An accepted configuration that has no effect is a maintenance trap.

Either implement retention semantics with explicit columns and tests or remove the fields from v0.1.

### 14.6 `TouchClient` is stale even when called

SQLite updates `last_used_at` in its column, but `GetClient` returns `LastUsedAt` from the unchanged JSON payload. The probe confirms a touch is not visible through `GetClient`. Before building eviction on this field, choose one authoritative representation and update/read it consistently.

### 14.7 HTTP parameter ambiguity

OAuth parameters are security bindings. The transport should reject duplicate scalar parameters instead of relying on `url.Values.Get`. It should not silently combine query and body values at token and revoke endpoints. Authorization query fields need count and size bounds before `strings.Fields` allocates scope lists.

### 14.8 Registration metadata is only partially interpreted

`grant_types` and `response_types` are parsed but ignored. A client can request unsupported metadata and receive a successful registration with different metadata. Validate supported exact sets or document and implement deterministic defaults when fields are omitted.

### 14.9 Audit is mostly decorative

Only successful client registration calls `e.audit`. Authorization, login, consent, code exchange, refresh, replay, revocation, and failures emit no events. The design required a safe audit outcome per transition. Either complete the port or remove the public promise for v0.1.

### 14.10 Secret source contract is inconsistent

`SecretSource.NewTokenID` exists and fixtures implement it, but `jwttokens` generates JTI values with its own `crypto/rand` helper. Choose one owner. Keeping an unused interface method makes test determinism and dependency requirements misleading.

### 14.11 SQLite schema/migration boundary is preliminary

The schema creates a version table but does not read, validate, or migrate versions. Expiry uses `json_extract` on serialized timestamps. Constraint classification relies on matching driver error strings. These choices are acceptable for a prototype but not for the advertised durable adapter.

Use numbered migrations, typed expiry columns, explicit constraints, and driver error codes where available.

### 14.12 JWT strength belongs in the reusable adapter

CoinVault checks for a 2048-bit RSA key, but `jwttokens.New` does not. Another consumer can instantiate the reusable library with a weak key. Security invariants owned by token issuance belong in `jwttokens`, not only in one consumer.

### 14.13 CoinVault route ownership remains coupled

`Provider.MountRoutes` mounts authorization-server routes through the MCP auth provider. The design wanted application-level mounting and a narrow MCP resource verifier. This coupling makes it harder to run one authorization server for separate MCP and RAG processes and complicates issuer-prefix routing.

## 15. Why normal tests and CI did not catch these issues

### 15.1 The test suite is scenario-thin

There are 13 test functions across seven test files. Direct statement coverage at review time was:

- HTTP transport: 38.5%;
- JWT: 79.0%;
- OAuth server: 60.2%;
- SQLite: 60.0%;
- oauthresource: 0%;
- overall direct package profile: 48.8%.

Coverage is not a security metric, but the uncovered symbols align with review findings: consent, revoke, identity callback, JWKS, `TouchClient`, `Prune`, and resource helpers have no direct handler tests.

### 15.2 Planned conformance suites were never created

The design explicitly required one shared store suite, sequence/model tests, fuzzing, failure paths, and complete HTTP flow tests. No files matching conformance or fuzz suites exist. Tests are package-local happy paths with a few reviewer regressions.

### 15.3 Fakes and production adapters disagree

The main engine lifecycle test uses `memorytest`. That fake cannot fail revocation and does not share SQLite time/pruning semantics. A test passing against it says little about durable failure behavior.

### 15.4 No fault injection

The critical missed cases all involve a dependency doing something unexpected:

- revalidator returns another subject or malformed status;
- store cannot persist revocation;
- store capacity is permanently occupied;
- proxy Host/TLS differs from public issuer;
- principal codec returns non-JSON bytes.

The fixture set had no systematic failure matrix, so each case appeared only when a reviewer imagined it.

### 15.5 Green static checks answer different questions

Vet, golangci-lint, GoSec, CodeQL, dependency review, secret scanning, and tests all passed on the head. They can catch unsafe APIs, known patterns, vulnerabilities, or exercised regressions. They do not prove OAuth workflow semantics, quota recovery, exact error disposition, or durable transition truth.

CodeQL did identify the redirect sink, but it cannot infer the cross-function exact-registration lookup. That finding should motivate an explicit trusted-redirect representation rather than confidence based on a green aggregate check.

### 15.6 Commits were too large for invariant-by-invariant review

The core implementation commit added 1,696 lines. The adapter commit added 1,435 lines and combined SQLite, JWT, HTTP, resource helpers, and tests. That is too much security-sensitive behavior for one checkpoint.

The design proposed one transition and one conformance slice at a time. The implementation grouped packages for speed, so reviewers had to reconstruct multiple state machines simultaneously.

### 15.7 Fixes were local rather than systemic

Each review round fixed the reported line and added a regression. Examples:

- transient capacity was fixed, but permanent clients were not modeled;
- subject mismatch was fixed, but invalid enum status was not handled exhaustively;
- issuer-derived URLs were fixed, but route-prefix ownership was not unified;
- body size was fixed, but parameter cardinality and query bounds were not.

A review finding should trigger a search for all instances of the violated invariant, not only the commented line.

### 15.8 Documentation checklists were not gates

The design still contains unchecked requirements for digest-only persistence, conformance, audit, fuzzing, RAG integration, and final smoke. Ticket tasks marked core/adapters/cutover complete even though these acceptance conditions were not executable.

The design was treated as explanatory prose rather than a traceable acceptance matrix.

### 15.9 Review completion was observed incorrectly

The prior session requested Codex review, polled CI checks, and inspected an earlier review list before the final Codex review completed. It then concluded there were no new inline findings. The review of head `6cf0ff2` completed later with four comments.

A reliable gate must require:

```text
review summary commit == current head
AND review status == completed
AND inline comments for current head have been classified
AND required checks for current head are complete
```

Polling checks alone is insufficient because review comments and workflow checks are separate asynchronous systems.

## 16. Systemic root causes

The individual findings cluster into six root causes.

### Root cause A — security state is not encoded strongly enough

Examples:

- `RedirectURI` does not distinguish parsed from registered/trusted;
- integer `RevalidationStatus` is not exhaustively matched;
- stored records contain raw token fields because engine and persistence models are the same;
- commit types allow arbitrary successors rather than constrained transitions.

**Remedy:** introduce types and commands that make invalid states difficult to represent.

### Root cause B — ownership is duplicated

Issuer, resources, policies, clocks, token service, route paths, and random token IDs have multiple owners.

**Remedy:** create one runtime assembly and explicit adapter views.

### Root cause C — lifecycle policy is incomplete

Capacities were added without recoverable client lifecycle, retention is not implemented, and activity timestamps are inconsistent.

**Remedy:** model admission, lease, use, expiry, retention, and deletion together.

### Root cause D — atomicity was interpreted as transaction use, not invariant enforcement

SQLite transactions are present, but several commits do not verify full predecessor/successor bindings.

**Remedy:** define an invariant checklist per transition and enforce it inside the transaction.

### Root cause E — tests mirror code paths rather than adversarial behavior

Happy-path engine and adapter tests dominate; dependency failures, malformed adapters, duplicate parameters, and persistence bytes are missing.

**Remedy:** conformance, fault injection, generated sequences, and storage introspection.

### Root cause F — process optimized for checkpoint completion

Large phase commits, task check-offs, and “all checks pass” summaries created a completion signal before review and acceptance criteria had converged.

**Remedy:** smaller invariant-based commits and evidence-backed completion gates.

## 17. Recommended target architecture

### 17.1 One validated runtime assembly

```go
type RuntimeConfig struct {
    Issuer      Issuer
    Endpoints   EndpointSet
    Resources   []ResourceConfig
    Scopes      ScopeSet
    TTLs        TTLPolicy
    State       StatePolicy
    HTTP        HTTPPolicy
}

type Runtime[A any] struct {
    config    RuntimeConfig       // immutable
    registry  ResourceRegistry    // built once
    clock     Clock               // one clock
    store     Store[A]
    tokens    TokenService[A]
    engine    *Engine[A]
}
```

Construction validates coherence once. HTTP metadata, engine decisions, JWT issuance, and resource adapters consume views from the same runtime.

### 17.2 Explicit endpoint set

For origin-only v0.1:

```go
func NewIssuer(raw string) (Issuer, error) {
    require https origin or loopback development
    reject query, fragment, userinfo
    reject non-root path
}
```

If path issuers are required:

```go
type EndpointSet struct {
    Issuer        url.URL
    MountPrefix   string
    Authorize     url.URL
    Consent       url.URL
    Token         url.URL
    Register      url.URL
    Revoke        url.URL
    JWKS          url.URL
    IdentityReply url.URL
}
```

All routes and links derive from this object; no string concatenation or hardcoded form action remains.

### 17.3 Trusted redirect capability

```go
type TrustedRedirect struct {
    uri RedirectURI // constructor unexported
}

func (e *Engine[A]) ResolveTrustedRedirect(
    ctx context.Context,
    clientID string,
    redirect string,
) (TrustedRedirect, error)
```

Only a registered exact match can produce it. Redirect builders accept `TrustedRedirect`, not a general URL.

### 17.4 Separate raw credentials from stored records

```go
type AuthorizationHandle struct {
    Raw    TransactionToken
    Digest CredentialDigest
}

type AuthorizationRecord struct {
    Digest          CredentialDigest
    ClientID        ClientID
    RedirectURI     RedirectURI
    State           string
    PKCEChallenge   PKCEChallenge
    RequestedScopes ScopeSet
    Resource        ResourceID
    ExpiresAt       time.Time
}
```

Apply the same pattern to consent. Raw values live only in the engine/HTTP result path.

### 17.5 Store transition commands with expected state

```go
type LoginTransition[A any] struct {
    AuthorizationDigest CredentialDigest
    Expected            AuthorizationBinding
    Principal           Principal[A]
    AvailableScopes     ScopeSet
    ConsentDigest       CredentialDigest
    ConsentExpiresAt    time.Time
    Now                 time.Time
}
```

The store loads the predecessor, compares `Expected`, computes or validates the successor, inserts it, and consumes the predecessor in one transaction.

### 17.6 Recoverable registration admission

```go
type RegistrationAdmission interface {
    AdmitRegistration(context.Context, RegistrationAttempt) error
}

type ClientLifecyclePolicy struct {
    Enabled            bool
    UnverifiedIdleTTL  time.Duration
    MaxClients         int
}
```

The HTTP adapter applies request-source rate controls. The store prunes idle unverified clients only when no live child transition references them. Successful authorization/token operations update activity atomically.

### 17.7 Explicit error taxonomy

Store errors must distinguish:

- semantic absence/binding/consumption/revocation;
- temporary infrastructure failure;
- context cancellation;
- corruption/invariant violation.

Protocol privacy maps `NotFound` to non-disclosing success where required. It must not map infrastructure failure to success.

## 18. Phased remediation plan

### Phase A — correct the record and freeze merge

- Mark the final four Codex findings unresolved.
- Attach this review to OH-AUTH-001.
- Do not tag, merge, or publish v0.1 yet.
- Keep unrelated RAG/deployment work from obscuring core remediation.

### Phase B — close immediate PR findings

1. propagate ineligible-family revocation failures;
2. remove registration `Location`;
3. reject issuer paths for v0.1 or implement a complete endpoint/mount prefix;
4. add protected/recoverable client registration admission;
5. add focused tests for each failure and lifecycle recovery.

### Phase C — close local security blockers

1. separate raw transaction/consent handles from stored records;
2. add a database-byte test proving no raw test credential occurs in any table;
3. classify revoke lookup errors and return temporary failure for infrastructure errors;
4. exhaustively switch revalidation status;
5. validate principal subject before consuming login state;
6. move RSA key-strength validation into `jwttokens`.

### Phase D — make transition commits authoritative

Implement and test predecessor/successor binding checks for every commit. Add exactly-one-winner concurrency tests and malformed-successor rejection tests.

### Phase E — unify runtime configuration and time

- choose origin-only or full path support;
- create one endpoint set;
- share issuer/resources/policy/token service through one assembly;
- inject one clock into engine, JWT, memory, and SQLite;
- remove or implement every policy field.

### Phase F — rebuild persistence lifecycle

- explicit schema migrations and version checks;
- typed expiry/consumed/revoked/activity columns;
- codec version metadata;
- recoverable client lifecycle;
- consistent activity reads/writes;
- retention tests;
- corruption and migration tests.

### Phase G — complete conformance and integration

- shared memory/SQLite store conformance;
- engine sequence/model suite;
- HTTP full-flow suite;
- fault-injection matrix;
- JWT negative matrix;
- oauthresource tests;
- CoinVault full OAuth integration;
- independent RAG consumer and cross-audience rejection.

### Phase H — final review and release gates

- `GOWORK=off` tests, race, vet, lint, GoSec, govulncheck;
- fuzz corpus and bounded fuzz run;
- Codex/security review against exact head;
- manually classify every non-outdated unresolved thread;
- complete the one final deployed smoke only after release-candidate deployment.

## 19. Required test architecture

### 19.1 Shared store conformance

```go
func RunStoreConformance[A any](
    t *testing.T,
    factory func(t *testing.T, clock Clock) Store[A],
)
```

Run identical cases against memory and SQLite:

- no raw credential persistence where introspection is available;
- wrong binding does not consume;
- expired predecessor cannot transition;
- one winner under concurrent commit;
- malformed successor rejected;
- refresh scopes never expand;
- replay revokes full family;
- failed revocation is observable;
- capacity recovers after expiry/retention;
- client capacity recovers without deleting active clients;
- injected clock controls every timestamp.

### 19.2 Fault-injection decorator

```go
type FaultStore[A any] struct {
    Store[A]
    RevokeRefreshFamilyFunc func(...) error
    CommitCodeExchangeFunc  func(...) error
    CommitRefreshFunc       func(...) error
}
```

Each engine transition should be tested when secrets, policy, revalidation, token issuance, audit, and store commits fail. Assertions must cover both returned error and durable predecessor state.

### 19.3 HTTP protocol tests

Use a real `httptest.Server`, redirects disabled, and a complete fake identity callback. Cover:

- all discovery and JWKS endpoints;
- RFC DCR defaults and unsupported metadata;
- registration disabled/rate-limited/capacity recovery;
- exact redirect and error redirect stages;
- root-only issuer rejection or prefix mounting;
- consent GET/POST headers, form action, expiry, replay, and malformed decisions;
- code exchange, refresh, replay, revoke, and store failures;
- duplicate scalar parameters and query/body conflicts;
- media types with valid parameters and invalid lookalikes;
- body, field, array, query, and header limits.

### 19.4 Persistence inspection

Open the temporary SQLite database and search every payload/column for known raw test credentials. Do not infer digest-only behavior from key shape.

```text
for each raw transaction, consent, code, refresh secret:
    assert database bytes do not contain raw secret
    assert expected SHA-256 digest exists
```

### 19.5 Generated transition sequences

Generate valid and invalid operation orderings and compare both stores to a small reference model. This catches sequence defects that one hand-written lifecycle misses.

### 19.6 Coverage use

Do not set a security claim based on a percentage. Use coverage to locate unexercised boundaries. No externally reachable handler or side-effecting store transition should remain at 0%.

## 20. Decision records

### Decision: do not merge the current head

- **Context:** Four latest PR findings and multiple local security-contract violations remain.
- **Options considered:** Merge and follow up; patch only four comments; complete systemic pre-merge remediation.
- **Decision:** Complete systemic pre-merge remediation.
- **Rationale:** This is a reusable authorization library; downstream consumers amplify defects.
- **Consequences:** RAG and deployment work pause behind a safer core gate.
- **Status:** proposed.

### Decision: constrain issuer paths in v0.1

- **Context:** Metadata accepts paths, but routes, callbacks, consent, and forms are root-bound.
- **Options considered:** keep partial support; implement complete prefix support now; reject paths.
- **Decision:** Reject non-root issuer paths unless a named consumer requirement justifies complete endpoint-set work.
- **Rationale:** Explicitly unsupported behavior is safer and simpler than inconsistent support.
- **Consequences:** Path-based deployments require a later focused feature.
- **Status:** proposed.

### Decision: omit registration management `Location`

- **Context:** No management endpoint or registration access token exists.
- **Options considered:** leave dangling URL; implement RFC 7592; omit header.
- **Decision:** Omit the header in v0.1.
- **Rationale:** Avoid advertising behavior the server does not provide.
- **Consequences:** Management remains a separate future feature.
- **Status:** proposed.

### Decision: make raw and stored credential types distinct

- **Context:** Shared domain records caused raw transaction and consent secrets to be serialized.
- **Options considered:** JSON tags on fields; custom marshalers; separate types.
- **Decision:** Separate engine handles from store records.
- **Rationale:** Type separation makes accidental persistence harder and tests clearer.
- **Consequences:** Store and engine APIs change before v0.1 stabilization.
- **Status:** proposed.

### Decision: make commit transitions authoritative

- **Context:** Transactions enforce one-time updates but not complete successor derivation.
- **Options considered:** trust engine; duplicate checks in store; let store construct successors.
- **Decision:** Store must verify expected predecessor and monotonic successor constraints inside the transaction.
- **Rationale:** Atomicity without invariant checks does not provide the advertised safety boundary.
- **Consequences:** Commit structs become richer and conformance tests become mandatory.
- **Status:** proposed.

### Decision: one clock and one runtime configuration

- **Context:** engine, JWT, HTTP, registry, and stores can disagree.
- **Options considered:** document caller responsibility; add equality checks; create one runtime assembly.
- **Decision:** Create one validated assembly and inject one clock everywhere.
- **Rationale:** Coherence should be constructed, not assumed.
- **Consequences:** Adapter constructors simplify, but public APIs change.
- **Status:** proposed.

## 21. Intern-oriented implementation checklist

Before changing code, the implementer should be able to explain:

- why a registered redirect is more trusted than a parsed redirect;
- why an OAuth privacy-preserving response can still return 503 on storage failure;
- why every refresh successor must be a subset of its predecessor;
- why code/refresh output is prepared before a one-time commit;
- why durable revocation must succeed before returning a revoked semantic;
- why client quota without lifecycle is a persistent denial of service;
- why fake and SQLite stores need one conformance suite;
- why an injected clock is ineffective if persistence uses wall time;
- why green CI does not imply a completed asynchronous review;
- why raw handles and persisted records should be different types.

For each implementation change:

1. state the violated invariant;
2. search all packages for the same invariant;
3. add a failing test at the lowest useful layer;
4. add an integration test if the boundary crosses layers;
5. implement the smallest coherent fix;
6. run the shared conformance suite;
7. document behavior and migration impact;
8. request review only after the head is pushed;
9. wait for the review result for that exact head;
10. classify every comment before declaring green.

## 22. File-by-file review map

### Core

- `pkg/oauthserver/config.go:15-57` — duplicated runtime policy and limits.
- `pkg/oauthserver/config.go:79-106` — validation; currently accepts issuer paths and unused retention settings.
- `pkg/oauthserver/config.go:109-133` — origin, redirect, and loopback semantics.
- `pkg/oauthserver/model.go:57-106` — raw transaction/consent fields and durable state models.
- `pkg/oauthserver/ports.go:8-137` — capability contracts; note unused `NewTokenID`, `TouchClient`, and broad Store interface.
- `pkg/oauthserver/engine.go:39-77` — DCR validation and permanent registration admission.
- `pkg/oauthserver/engine.go:99-116` — exact registered redirect lookup.
- `pkg/oauthserver/engine.go:123-168` — authorization stage and trusted-error boundary.
- `pkg/oauthserver/engine.go:179-208` — principal acceptance and root-relative consent URL.
- `pkg/oauthserver/engine.go:284-381` — code/refresh output ordering, revalidation, and ignored revocation failure.
- `pkg/oauthserver/engine.go:384-394` — revocation error swallowing.
- `pkg/oauthserver/engine.go:436-438` — audit helper, called only by registration.

### HTTP

- `pkg/httptransport/server.go:19-26` — duplicate issuer/resources/token/policy configuration.
- `pkg/httptransport/server.go:49-58` — root-only mount paths.
- `pkg/httptransport/server.go:103-131` — DCR DTO, ignored metadata, and dangling Location.
- `pkg/httptransport/server.go:133-159` — authorization errors and login-starter failure disposition.
- `pkg/httptransport/server.go:174-221` — consent rendering/submission.
- `pkg/httptransport/server.go:224-269` — token and revoke handlers.
- `pkg/httptransport/server.go:275-289` — identity callback and root-relative consent redirect.
- `pkg/httptransport/server.go:292-335` — body parsing, media types, cardinality, and bounds.
- `pkg/httptransport/server.go:360-379` — trusted error redirect and issuer string concatenation.
- `pkg/httptransport/server.go:388` — hardcoded root consent form action.

### SQLite

- `pkg/sqlitestore/store.go:51-74` — schema creation without migration enforcement.
- `pkg/sqlitestore/store.go:76-103` — permanent client count.
- `pkg/sqlitestore/store.go:105-132` — stale activity representation.
- `pkg/sqlitestore/store.go:134-160` — raw authorization token serialization.
- `pkg/sqlitestore/store.go:182-223` — raw consent token serialization and weak transition derivation checks.
- `pkg/sqlitestore/store.go:250-294` — consent-to-code transition checks.
- `pkg/sqlitestore/store.go:322-365` — code-to-refresh transition checks.
- `pkg/sqlitestore/store.go:400-452` — rotation and replay transaction.
- `pkg/sqlitestore/store.go:454-467` — family revocation.
- `pkg/sqlitestore/store.go:469-520` — wall-clock pruning, ignored retention policy, JSON expiry.
- `pkg/sqlitestore/store.go:536-547` — codec envelopes.

### JWT and resource

- `pkg/jwttokens/service.go:29-61` — duplicated issuer/clock and missing RSA strength validation.
- `pkg/jwttokens/service.go:63-94` — access-token claims and independent JTI generation.
- `pkg/jwttokens/service.go:96-148` — fixed-trust verification and exact audience.
- `pkg/oauthresource/token.go` — untested bearer extraction/verification.
- `pkg/oauthresource/metadata.go` — untested metadata/challenge output.

### Tests and process

- `pkg/oauthserver/core_test.go` — one broad lifecycle; useful but insufficient as a model suite.
- `pkg/oauthserver/review_test.go` — narrow second-round regressions.
- `pkg/httptransport/server_test.go` — no consent/callback/revoke/full token flow.
- `pkg/sqlitestore/store_test.go` — transition happy path; test name does not inspect plaintext persistence.
- `pkg/sqlitestore/prune_test.go` — one transient expiry case only.
- `pkg/jwttokens/service_test.go` — strongest focused package coverage, still missing full negative matrix.
- `.github/workflows/` — green static/security workflows do not gate review-thread disposition or conformance.

### CoinVault

- `coinvault/internal/mcpoauth/provider.go:65-115` — runtime assembly and duplicated configuration.
- `coinvault/internal/mcpoauth/provider.go:126-129` — authorization routes still owned by MCP provider.
- `coinvault/internal/mcpoauth/provider.go:143-166` — callback adapter and principal validation.
- `coinvault/internal/mcpoauth/provider.go:199-215` — refresh revalidation adapter.
- `coinvault/internal/mcpoauth/provider_test.go` — shallow construction/metadata test only.
- `coinvault/cmd/coinvault/cmds/mcp.go` — SQLite and provider composition root.

## 23. Validation evidence

Commands executed during this review:

```bash
GOWORK=off go test ./... -count=1 -coverprofile=/tmp/oh-auth-cover.out
GOWORK=off go test ./... -count=1 -coverpkg=./pkg/... \
  -coverprofile=/tmp/oh-auth-cover-all.out
GOWORK=off go tool cover -func=/tmp/oh-auth-cover.out
scripts/03-probe-sqlite-boundaries.sh
gh api repos/go-go-golems/oh-auth/pulls/1/comments --paginate
```

Observed results:

- ordinary tests passed;
- 13 test functions exist;
- no conformance or fuzz files exist;
- direct statement profile reported 48.8% total;
- raw transaction and consent credentials were found in SQLite payloads;
- `TouchClient` was not reflected by `GetClient`;
- PR evidence contained 15 inline comments, including four on final head `6cf0ff2`.

## 24. Open questions

1. Is a path-based issuer required by any planned deployment? If not, reject it in v0.1.
2. What application-level admission signal is available for MCP dynamic registration: source rate limit, deployment token, proof-of-work, operator approval, or another policy?
3. What idle lifetime is acceptable for unverified clients, and can clients safely re-register after eviction?
4. Should consumed records be retained for audit/replay evidence, and for how long per record category?
5. Is SQLite intended for one process only, or can authorization and resource components share it across processes?
6. Should the store construct successors or only verify engine-built successors?
7. Is the public audit port part of v0.1, or should it remain internal until complete?
8. Must existing CoinVault clients/grants survive the persistence schema correction?

None of these questions justifies merging known false-success revocation or raw-secret persistence. Those have safe default answers and should be fixed first.

## 25. Final handoff

The architecture is salvageable and has a good core direction. The correct response is not a rewrite and not a collection of compatibility shims. Preserve the package boundaries, typed principals, exact audiences, scope intersection, PKCE, and fixed JWT trust. Tighten the state representations, make transitions authoritative, unify configuration/time, and build the conformance/failure suites the design already called for.

The next developer should start with these files in order:

1. `pkg/oauthserver/model.go` and `ports.go` — separate raw and stored types; redesign transition commands.
2. `pkg/oauthserver/engine.go` — revocation, exhaustive revalidation, principal validation, and error disposition.
3. `pkg/sqlitestore/store.go` — digest-only persistence, authoritative commits, clock/lifecycle/schema.
4. `pkg/httptransport/server.go` — registration admission, issuer route policy, Location removal, and strict parameter handling.
5. shared conformance/fault-injection tests before returning to RAG or deployment work.

## 26. Post-review implementation outcome

The senior review was followed by five implementation phases and focused exact-head review rounds. The merge recommendation in Section 3 described the pre-remediation branch; the implementation now closes the named security and correctness blockers while intentionally avoiding a larger runtime framework, path-prefix subsystem, registration-management protocol, post-expiry retention system, or deployed smoke expansion.

### 26.1 Closed findings

- Dynamic clients have a recoverable idle lease and are preserved while any live authorization, consent, code, or refresh state references them.
- Active refresh-family admission is separate from retained replay generations; each family has an explicit generation bound.
- Ineligibility and replay revocation failures propagate as temporary errors rather than false durable success.
- Consumed-token replay is revoked before external revalidation, policy, signing, or secret generation.
- Transaction and consent handles are omitted from durable payloads and verified by database-byte tests.
- Memory and SQLite use injected clocks, protocol-expiry pruning, transition validators, collision checks, and shared conformance cases.
- Issuers are explicitly origin-only; registration no longer advertises nonexistent management.
- OAuth discovery no longer claims OIDC and advertises token authentication method `none`.
- DCR safely ignores bounded extension metadata and uses a dedicated client-ID generator.
- Consent discloses an authorization deadline that is carried through the code into refresh expiry.
- HTTP parsing rejects duplicate scalar bindings and query/body ambiguity while remaining media-type interoperable.
- Engine, HTTP, token, registry, clock, JWT key, schema version, and audit contracts are coherent and tested.
- CoinVault completes a GEC-backed registration, authorization, callback, consent, code, JWT validation flow against the published pseudo-version.

### 26.2 Deterministic evidence

- normal tests, race tests, vet, golangci-lint, GoSec, govulncheck, and a bounded parser fuzz run pass;
- the complete HTTP authorization-code/refresh/revoke flow runs under `httptest`;
- shared memory/SQLite conformance covers expiry admission, invalid-binding retry, and concurrent final capacity;
- direct statement coverage increased from 48.8% to 59.2%, with HTTP at 72.7% and oauthresource at 66.7%;
- CoinVault passes its full pre-push build, lint, security, vulnerability, and test suite with the hardened dependency;
- no deployed smoke test was added or run.

### 26.3 Deliberate stop rule

Repeated broad review reached diminishing returns after authority, persistence, lifecycle, replay, and interoperability invariants were covered. One final reviewed suggestion—distinct HTTP 413/415 responses instead of the existing bounded OAuth `400 invalid_request` response—was classified as optional response polish, not a security or functional blocker. The low-cost refresh-digest collision found in the same review was fixed in `c0544d83` and tested in both code-exchange and rotation paths. No further broad automated review was requested, per the shipping decision.

Remaining ticket phases are product integration work rather than PR #1 library blockers: independent RAG audience isolation and the previously planned final deployed acceptance smoke.

## 27. References

- [oh-auth PR #1](https://github.com/go-go-golems/oh-auth/pull/1)
- `sources/github/pr-1-review-comments.json`
- `design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md`
- `design-doc/02-deferred-owasp-hardening-and-higher-assurance-roadmap.md`
- `reference/01-investigation-diary.md`
- RFC 6749 — OAuth 2.0 Authorization Framework
- RFC 7009 — Token Revocation
- RFC 7591 — Dynamic Client Registration
- RFC 7636 — PKCE
- RFC 8414 — Authorization Server Metadata
- RFC 8707 — Resource Indicators
- RFC 9728 — Protected Resource Metadata
- OWASP evidence manifest: `sources/owasp/README.md`
