---
Title: Deferred OWASP Hardening and Higher Assurance Roadmap
Ticket: OH-AUTH-001
Status: active
Topics:
    - oauth
    - security
    - architecture
    - golang
    - library
DocType: design-doc
Intent: long-term
Owners: []
RelatedFiles:
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md
      Note: Defines the v0.1 shipping baseline from which these controls are deferred
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/sources/owasp/README.md
      Note: OWASP evidence and canonical source index for future hardening
ExternalSources:
    - https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md
    - https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
    - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
    - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
    - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
    - https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses
Summary: Preserve nonessential OWASP and higher-assurance ideas outside the oh-auth v0.1 shipping path, with explicit adoption triggers and API sketches.
LastUpdated: 2026-09-02T01:10:00-04:00
WhatFor: Keep future grant management, online revocation, ASVS assurance, sender constraints, PAR/JAR, and exhaustive security controls available without burdening v0.1.
WhenToUse: Consult only after the minimal OAuth extraction is working, or when a concrete compliance, revocation, or high-assurance requirement appears.
---


# Deferred OWASP Hardening and Higher Assurance Roadmap

## 1. Executive summary

The OWASP review initially expanded the v0.1 extraction design into a much larger authorization-management system. The useful research is retained here, but none of the features in this document is required to ship the first reusable `oh-auth` release.

The v0.1 shipping contract remains in [Composable OAuth Server Extraction Analysis, Design, and Implementation Guide](01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md). It includes the small, practical delta: consent headers and one-time form-token semantics, consent lifetime disclosure, fixed JWT trust, strict HTTP boundaries, deny-by-default consumer enforcement, and focused WSTG tests.

This roadmap contains controls that introduce new persistent concepts, runtime dependencies, user-management surfaces, client/protocol requirements, or broad compliance claims:

- durable authorization-grant IDs and versions;
- online grant-status checks and immediate JWT invalidation;
- revocation of every token after authorization-code replay;
- user grant/consent inventory, narrowing, and revocation UI;
- a separate browser-flow cookie binding beyond the one-time consent token;
- authentication-method/strength/recentness propagation;
- formal ASVS Level 2 or Level 3 profiles;
- DPoP, mTLS, PAR, JAR, RAR, and confidential clients;
- exhaustive audit/event schemas and resource-budget frameworks;
- the full OWASP matrix as a blocking release gate.

These ideas are not rejected. Each requires a concrete trigger and its own accepted implementation ticket before entering the shipping design.

## 2. Why these features are deferred

The original extraction already has a substantial surface: typed principal data, exact resources, canonical scopes, protocol transitions, SQLite, JWT, HTTP, identity adapters, MCP/RAG adapters, DCR, consent, refresh rotation, revalidation, and cleanup. The deferred controls add different kinds of complexity:

| Deferred area | Additional complexity |
|---|---|
| Durable grant status | New grant table/state/version, JWT claims, store operations, migration, resource verification behavior |
| Remote status check | Request-time cross-service dependency, service authentication, timeouts, caching, fail-open/closed choices, monitoring |
| User grant management | Authenticated account UI/API, ownership checks, scope reduction, revocation semantics, support workflow |
| Code-replay token revocation | Code-to-grant linkage and immediate access-token invalidation beyond existing one-time rejection |
| Browser-flow cookie | Cookie lifecycle, callback binding, proxy/origin semantics, more integration tests |
| Authentication context | Identity-provider mapping and per-resource method/strength/recentness policy |
| DPoP/mTLS | Client key management, proof validation, nonce/replay handling, resource-server changes, host compatibility |
| PAR/JAR/RAR | New endpoints and signed request objects; confidential-client authentication and policy |
| Compliance profiles | Requirement applicability, evidence maintenance, conformance tests, release assertions |
| Full audit/budget framework | Schema governance, queues/sinks, retention, alerts, performance and failure-mode tests |

Implementing the first five together can add roughly 35–50% to the initial integration effort and creates an availability coupling between resource servers and authorization state. They should not be introduced merely because an OWASP document describes an advanced or compliance-oriented control.

## 3. Promotion rule

A deferred feature moves into the main design only when all of the following are true:

1. A named consumer, threat, compliance requirement, or incident needs it.
2. Target MCP/RAG clients and deployment infrastructure can support it.
3. The owner accepts the operational costs and failure modes.
4. A focused design and executable acceptance criteria exist.
5. It does not silently alter the v0.1 security or availability contract.

Examples:

- “We want ASVS Level 2 certification” is a valid trigger for full consent/grant management and code-replay token revocation.
- “Access tokens must become invalid within 30 seconds after an employee is disabled” is a valid trigger for grant status/introspection.
- “Claude and ChatGPT both support DPoP for this connector” may trigger a sender-constrained-token design.
- “OWASP mentions DPoP” by itself is not a product requirement.

## 4. Durable authorization grants and immediate revocation

### 4.1 Problem addressed

The v0.1 design has short-lived JWT access tokens and rotating opaque refresh families. Explicit revocation prevents future refresh, but an already-issued access token remains usable until its short expiry. Replaying a consumed authorization code is rejected but does not require online access-token revocation.

OWASP ASVS 10.4.2 expects tokens related to a correctly replayed code to be revoked, and ASVS 10.4.9/10.7.3 expects user-driven grant/consent management. One durable grant object can support all three.

### 4.2 Deferred model

```go
type GrantID string

type GrantStatus uint8

const (
    GrantStatusUnknown GrantStatus = iota
    GrantStatusActive
    GrantStatusRevoked
    GrantStatusExpired
)

type AuthorizationGrant[A any] struct {
    ID        GrantID
    Version   uint64
    Status    GrantStatus
    ClientID  ClientID
    Principal Principal[A]
    Resource  ResourceID
    Scopes    ScopeSet
    CreatedAt time.Time
    ExpiresAt time.Time
    RevokedAt time.Time
}
```

A successful code exchange would:

1. create one `AuthorizationGrant`;
2. record its ID on the consumed code;
3. include `grant_id` and `grant_version` in access tokens;
4. link the refresh family to the same grant.

A correctly bound replayed code would revoke the linked grant. A wrong client, redirect, or verifier must not revoke the legitimate grant.

### 4.3 Deferred store API

```go
type GrantStore[A any] interface {
    GetGrant(context.Context, GrantID) (AuthorizationGrant[A], error)
    ListGrants(context.Context, Subject) ([]AuthorizationGrant[A], error)
    ReduceGrant(context.Context, Subject, GrantID, ScopeSet, time.Time) error
    RevokeGrant(context.Context, Subject, GrantID, time.Time) error
    RevokeGrantForCodeReplay(context.Context, CodeExchangeBinding, time.Time) error
}
```

`ReduceGrant` accepts only a subset and increments `Version`. Old access tokens then carry a stale version.

### 4.4 Adoption trigger

Promote this model when immediate access-token revocation, ASVS Level 2 evidence, or user consent management is a product requirement. Do not add it only to improve theoretical completeness.

## 5. Grant-status propagation to separate resource servers

### 5.1 Deferred interface

```go
type GrantStatusReader interface {
    CurrentGrantStatus(
        context.Context,
        GrantID,
    ) (GrantStatus, uint64, error)
}
```

A resource verifier would compose:

```text
JWT signature/claims
  -> exact issuer and audience
  -> grant active and version current
  -> route/tool scope policy
```

### 5.2 Deployment options

- in-process store adapter when authorization and resource server are colocated;
- service-authenticated internal status endpoint;
- RFC 7662 introspection;
- signed revocation/status list;
- short-lived cache with a declared maximum propagation delay.

Each option has availability and consistency tradeoffs. High-value routes might fail closed when status cannot be established, while lower-risk routes might accept a recently cached active status. This must be a deployment decision, not a hidden library default.

### 5.3 Adoption trigger

Promote only with a required revocation propagation objective, for example “employee disablement takes effect within 30 seconds.” Until then, short access-token TTL plus refresh revalidation is simpler.

## 6. User grant and consent management

ASVS 10.4.9 and 10.7.3 describe user review, modification, and revocation. A future application-authenticated surface could expose:

```go
type GrantSummary struct {
    ID          GrantID
    ClientName  string
    ClientTrust ClientTrust
    Resource    ResourceID
    Scopes      ScopeSet
    CreatedAt   time.Time
    ExpiresAt   time.Time
}

func (e *Engine[A]) ListGrants(ctx context.Context, subject Subject) ([]GrantSummary, error)
func (e *Engine[A]) ReduceGrant(ctx context.Context, subject Subject, id GrantID, scopes ScopeSet) error
func (e *Engine[A]) RevokeGrant(ctx context.Context, subject Subject, id GrantID) error
```

Requirements:

- authenticate the account-management session strongly;
- check subject ownership server-side on every operation;
- never allow scope expansion;
- revalidate current identity for sensitive changes;
- invalidate affected refresh tokens;
- define access-token revocation timing;
- audit changes without logging credentials.

This is OAuth account administration, not core code-flow mechanics. It should be hosted only after a concrete product surface is chosen.

## 7. Additional browser-flow binding

The minimal design uses the existing random, expiring, one-time consent token as a synchronizer CSRF token, with no-store, no external resources, CSP form restrictions, no-referrer, and anti-framing headers.

A stronger future design may add a separate authorization-server browser-flow cookie:

```text
__Host-oh-auth-flow=<random>
Secure; HttpOnly; SameSite=Lax; Path=/; no Domain
```

The transaction and consent store only its digest. Consent rendering and submission require both the one-time form token and matching cookie. Fetch Metadata and Origin/Referer checks provide defense in depth.

Promote this only if threat modeling, penetration testing, shared-domain deployment, or token-leak evidence shows that the one-time form token and headers are insufficient.

## 8. Authentication context propagation

A future principal may include:

```go
type AuthenticationContext struct {
    AuthenticatedAt time.Time
    Methods         []string
    Assurance       string
}
```

Resource policies can then require recent authentication, MFA, or a named assurance level. This maps to ASVS 10.3.4.

It is deferred because every identity adapter must map trustworthy source claims and every resource policy must define requirements. Adding empty fields without enforcement would create false assurance.

## 9. Higher-assurance token and request profiles

### 9.1 Sender-constrained access and refresh tokens

ASVS Level 3 requires DPoP or mTLS-bound access tokens. This affects:

- client key generation/storage;
- authorization request or token endpoint binding;
- `cnf` claims;
- DPoP proof JWT parsing;
- method/URL/access-token hash validation;
- proof replay caches and nonce handling;
- MCP and RAG request adapters;
- host interoperability.

Do not advertise DPoP/mTLS until the authorization server, target hosts, and every resource server enforce it end to end.

### 9.2 PAR, JAR, RAR, and confidential clients

Deferred controls include:

- Pushed Authorization Requests (PAR);
- JWT-Secured Authorization Requests (JAR);
- Rich Authorization Requests (`authorization_details`);
- confidential-client authentication with mTLS or `private_key_jwt`;
- client-specific response-mode policies.

These introduce new endpoints, signing/trust relationships, request-object lifecycles, and client administration. They are not needed for current public MCP hosts.

### 9.3 Deferred profile API

If eventually useful:

```go
type SecurityProfile string

const (
    SecurityProfileStandard      SecurityProfile = "standard"
    SecurityProfileHighAssurance SecurityProfile = "high_assurance"
)
```

`high_assurance` must fail construction unless all required controls are present. A profile label must never be accepted as documentation-only configuration.

## 10. Expanded audit and resource governance

The main design already excludes credentials from logs and bounds registration/state. Future governance may add:

- a versioned audit event schema;
- mandatory interaction identifiers;
- pseudonymized subject/grant identifiers;
- log injection sanitization contracts;
- durable audit sinks and dropped-event alerts;
- key lifecycle events and compromise workflows;
- audit retention/access policy;
- HTTP concurrency and cryptographic-work budgets;
- SQLite database/WAL/disk high-water monitoring;
- external identity-service request/spend budgets;
- failure/full-disk simulations.

These are valuable operational maturity controls. They should be added with the deployment monitoring stack rather than forced into the first library API.

## 11. Full ASVS V10 crosswalk

This is reference material, not the v0.1 release claim.

### 11.1 Generic, client, and resource server

| Requirement | v0.1 position | Future work |
|---|---|---|
| V10.1.1 tokens only to necessary components | Consumer obligation | Secure client storage guidance/tests |
| V10.1.2 same transaction/user agent | PKCE/state plus one-time consent token | Optional browser-flow cookie |
| V10.2.1 client CSRF | Consumer obligation | Example-client conformance |
| V10.2.2 mix-up defense | Consumer obligation | Issuer response validation |
| V10.2.3 minimum requested scopes | Recommended | Client policy tests |
| V10.3.1 exact audience | Included | N/A |
| V10.3.2 enforce delegated claims | Included | N/A |
| V10.3.3 stable issuer+subject identity | Consumer guidance | Explicit identity key type |
| V10.3.4 auth strength/recentness | Deferred | `AuthenticationContext` |
| V10.3.5 sender-constrained access | Deferred Level 3 | DPoP/mTLS |

### 11.2 Authorization server

| Requirement | v0.1 position | Future work |
|---|---|---|
| V10.4.1 exact redirect | Included | N/A |
| V10.4.2 replayed code revokes issued tokens | Replay rejected | Durable grant/code linkage and immediate revocation |
| V10.4.3 short code | Included; one minute | N/A |
| V10.4.4 only needed grants | Included; code/refresh only | N/A |
| V10.4.5 refresh replay | Included; rotation/family revocation | Optional DPoP/mTLS |
| V10.4.6 mandatory PKCE | Included; S256 only | N/A |
| V10.4.7 unauthenticated DCR | Included through validation, bounds, warning, consent | N/A |
| V10.4.8 absolute refresh expiry | Included | N/A |
| V10.4.9 user revocation | Client token revocation only | User grant-management surface |
| V10.4.10 confidential client auth | Not applicable | Separate confidential-client design |
| V10.4.11 required scopes only | Included | N/A |
| V10.4.12 response-mode policy | Only default code response | PAR/JAR profile if needed |
| V10.4.13 code with PAR | Deferred Level 3 | PAR |
| V10.4.14 sender-constrained access | Deferred Level 3 | DPoP/mTLS |
| V10.4.15 protected authorization details | Not applicable | RAR/PAR/JAR |
| V10.4.16 strong confidential client | Not applicable | mTLS/private-key JWT |

### 11.3 Consent management

| Requirement | v0.1 position | Future work |
|---|---|---|
| V10.7.1 explicit unverified consent | Included | N/A |
| V10.7.2 clear information/lifetime | Included in minimal delta | N/A |
| V10.7.3 review/modify/revoke | Deferred | User grant-management surface |

Primary source: [OWASP ASVS 5.0 V10](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md).

## 12. Expanded OWASP verification matrix

The v0.1 design retains a focused subset. A future compliance/security program can expand to the matrix below as deterministic conformance, penetration, or operational tests. **None of these cases should be added to the routine deployed smoke.** A broad matrix is valuable precisely because it can run against fakes, injected clocks, temporary stores, and isolated security environments without slowing normal development or damaging shared grants.

| Area | Additional tests |
|---|---|
| Code replay | Verify linked access and refresh tokens become invalid immediately |
| Grant management | Other-subject denial, subset-only reduction, stale version, revoked grant |
| Status service | cache expiry, outage, latency, service authentication, fail-open/closed behavior |
| Authentication context | insufficient method, assurance, or recentness |
| DPoP/mTLS | proof signature, URL/method/hash binding, nonce, replay, certificate binding |
| PAR/JAR | request URI ownership, expiry, one-time use, signature/issuer/audience |
| Account UI | session security, CSRF, reauthentication, ownership, audit |
| Audit | CR/LF injection, sink outage, full disk, dropped events, PII/token exclusion |
| Resource limits | concurrency, crypto CPU, WAL growth, log volume, upstream cost |

Testing classification:

- grant/code/status logic: unit and temporary-SQLite integration;
- DPoP/PAR/JAR: protocol conformance with local fixtures;
- account UI: browser/security integration;
- audit and resource budgets: isolated operational exercise;
- external penetration: scheduled release/security activity;
- deployed smoke: no deferred cases unless a future accepted ticket proves one essential and non-destructive.

Relevant sources:

- [OWASP OAuth2 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OWASP WSTG OAuth Authorization Server Weaknesses](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses)
- [OWASP Authorization Regression Testing](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html)
- [OWASP API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- local manifest: `sources/owasp/README.md`

## 13. Decision records

### Decision: do not make ASVS compliance a v0.1 goal

- **Context:** Full ASVS applicability adds grant management, online status, and higher-assurance protocol work beyond the current consumer need.
- **Options considered:** retain the expanded main design; ignore OWASP; keep a minimal shipping baseline and separate roadmap.
- **Decision:** Ship an OWASP-informed v0.1 without an ASVS certification claim.
- **Rationale:** Preserve security essentials while avoiding premature operational and product surfaces.
- **Consequences:** Some ASVS rows remain documented gaps rather than implementation requirements.
- **Status:** accepted

### Decision: require concrete triggers for deferred controls

- **Context:** Security controls can reduce one risk while adding availability, key-management, and interoperability risks.
- **Options considered:** implement proactively; discard; gate promotion on explicit need.
- **Decision:** Promote only through a focused ticket with consumer and operational evidence.
- **Rationale:** Keeps the library composable and shippable.
- **Consequences:** This roadmap must be revisited when requirements change.
- **Status:** accepted

## 14. Suggested future work order

If requirements eventually justify the deferred work:

1. Define the revocation propagation objective.
2. Add durable grant ID/status/version and code linkage.
3. Add status reading for one colocated resource server.
4. Add a protected remote status transport only when a separate server needs it.
5. Add user listing/reduction/revocation through a chosen authenticated UI.
6. Add authentication context only for a route that enforces it.
7. Evaluate DPoP support in target hosts before implementing proofs.
8. Add PAR/JAR/confidential clients only with a concrete client.
9. Establish an ASVS evidence program only when a compliance owner exists.

## 15. Open questions

- What event would require access-token invalidation faster than the existing short TTL?
- Are target MCP hosts capable of DPoP or mTLS?
- Which service would own an authenticated grant-management UI?
- What failure semantics would remote grant status use?
- Is ASVS certification or customer evidence likely to become a requirement?

## 16. References and local evidence

- Shipping design: [Composable OAuth Server Extraction Analysis, Design, and Implementation Guide](01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md)
- OWASP source manifest: `sources/owasp/README.md`
- Checksums: `sources/owasp/SHA256SUMS`
- Reproducible source downloader: `scripts/01-download-owasp-sources.sh`
- ASVS V10: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md
- OAuth2 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- WSTG OAuth testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses
