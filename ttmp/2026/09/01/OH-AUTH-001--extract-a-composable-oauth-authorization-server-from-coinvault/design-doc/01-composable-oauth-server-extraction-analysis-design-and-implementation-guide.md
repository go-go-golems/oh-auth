---
Title: Composable OAuth Server Extraction Analysis Design and Implementation Guide
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
    - Path: repo://go.mod
      Note: Shows the new repository's current template module and toolchain baseline
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/sources/owasp/README.md
      Note: Crosslinked OWASP evidence for the minimal shipping delta
    - Path: ws://coinvault/internal/mcpauthz/capabilities.go
      Note: Defines application-owned capability-to-scope policy
    - Path: ws://coinvault/internal/mcpauthz/gec_client.go
      Note: Defines application-owned identity and revalidation behavior that remains outside core
    - Path: ws://coinvault/internal/mcpoauth/provider.go
      Note: Primary extraction source for protocol, transitions, HTTP, JWT, and MCP coupling
    - Path: ws://go-go-mcp/pkg/embeddable/auth_provider.go
      Note: Defines the current MCP resource-server provider integration boundary
    - Path: ws://go-go-mcp/pkg/embeddable/official_backend.go
      Note: Shows bearer enforcement, protected-resource metadata, and principal context injection
ExternalSources:
    - https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
    - https://www.rfc-editor.org/rfc/rfc6749
    - https://www.rfc-editor.org/rfc/rfc7591
    - https://www.rfc-editor.org/rfc/rfc7636
    - https://www.rfc-editor.org/rfc/rfc7009
    - https://www.rfc-editor.org/rfc/rfc8414
    - https://www.rfc-editor.org/rfc/rfc8707
    - https://www.rfc-editor.org/rfc/rfc9728
    - https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
    - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses
Summary: Extract CoinVault's OAuth authorization server into a reusable, typed, transition-oriented Go library for independent MCP and RAG resource servers.
LastUpdated: 2026-09-02T00:50:00-04:00
WhatFor: Give a new engineer the architecture, APIs, invariants, package map, extraction sequence, and validation plan for the oh-auth library.
WhenToUse: Read before implementing oh-auth, moving CoinVault OAuth code, or integrating authorization into an MCP or RAG server.
---




# Composable OAuth Server Extraction Analysis, Design, and Implementation Guide

## 1. Executive summary

`oh-auth` will be a reusable Go library for running an OAuth authorization server and validating its access tokens from independent resource servers. Its first implementation source is CoinVault's working GEC-backed OAuth flow. Its intended consumers include a standalone MCP server and one or more RAG HTTP servers, which may be separate processes but need consistent client registration, employee consent, token issuance, refresh, revocation, and bearer-token validation.

The extraction must not merely copy `internal/mcpoauth` into another repository. The current implementation combines six concerns in one provider:

1. OAuth protocol parsing and responses.
2. Authorization state transitions.
3. SQLite persistence.
4. JWT signing and verification.
5. CoinVault capability policy.
6. GEC browser and service integration.

The proposed library separates these concerns around a small, typed engine. The engine accepts explicit commands, validates them, computes one result, and asks a store to commit the corresponding state transition atomically. Application-specific identity and scope policy enter through narrow interfaces. HTTP, SQLite, JWT, MCP, and RAG integration remain adapters around the engine rather than being embedded in its rules.

The core consistency rules are simple to state:

- every grant is bound to one client, principal, redirect, PKCE challenge, and resource;
- every one-time credential can advance the flow at most once;
- granted scopes can only stay the same or become narrower after initial consent;
- a temporary dependency failure issues no authority and destroys no retryable authority;
- persistent state is bounded and has an explicit lifecycle;
- dynamic client names are unverified unless independently configured as trusted;
- application code can contribute identity and policy but cannot bypass the engine's grant intersection.

These rules have a clean formal interpretation as deterministic state transitions and monotonic authority reduction, but the public API uses ordinary names such as `BeginAuthorization`, `CompleteLogin`, `ApproveConsent`, `ExchangeCode`, and `Refresh`. Consumers should not need mathematics terminology to use the package correctly.

The v0.1 design is OWASP-informed rather than an ASVS compliance claim. The shipping delta is intentionally small: explicit consent anti-framing/no-referrer headers, use of the existing unguessable one-time consent token as the form CSRF token, authorization-lifetime disclosure, fixed JWT algorithm/type/key trust, strict HTTP method/content/size/timeout handling, deny-by-default consumer enforcement, and a focused WSTG-derived negative test set. More expensive grant-status, user-management, DPoP/mTLS, PAR/JAR, and higher-assurance work is isolated in [Deferred OWASP Hardening and Higher Assurance Roadmap](02-deferred-owasp-hardening-and-higher-assurance-roadmap.md).

## 2. Audience and reading order

This document assumes the reader is a new Go engineer who understands HTTP but may not have implemented OAuth.

Recommended reading order:

1. Section 3 defines the actors and credentials.
2. Section 4 walks through the current CoinVault flow.
3. Sections 5 and 6 explain the extraction problem and the design principles.
4. Sections 7–14 define packages, types, interfaces, state transitions, persistence, and HTTP.
5. Section 18 gives the file-by-file implementation sequence.
6. Sections 19–21 define testing, migration, and review.

Do not begin by moving files. First implement the core value types and transition tests in `oh-auth`; then migrate one working transition at a time.

## 3. OAuth vocabulary and system roles

### 3.1 Human and identity concepts

- **User or employee:** The human who wants to let a client access a protected service.
- **Identity provider:** A system that authenticates the human. In CoinVault's first integration, Google Workspace and AWS ALB feed a GEC employee session.
- **Principal:** The authorization server's narrow, validated description of an authenticated actor. A principal has a stable subject and application-specific attributes used by policy.
- **Subject:** A stable identifier such as `gec-employee:42`. Email and display name are presentation fields, not durable identity keys.
- **Capability or entitlement:** Durable application policy attached to the principal, such as GEC's `coinvault_sql_read`.
- **Authorization version:** A monotonically increasing policy version that changes when employee status or capabilities change.

A principal is not a browser cookie, Google token, refresh token, or MCP session. It is the authorization result that the identity adapter gives the OAuth engine.

### 3.2 OAuth roles

- **Authorization server:** The component that registers clients, coordinates login and consent, and issues access and refresh tokens. `oh-auth` implements this role.
- **Resource server:** An API that accepts access tokens. The MCP and RAG servers are resource servers.
- **OAuth client:** The application asking for delegated access. Claude, ChatGPT, a desktop app, or another service can be a client.
- **Public client:** A client that cannot keep a client secret. MCP hosts use PKCE instead of a secret.
- **Dynamic client registration (DCR):** The protocol by which a client posts redirect URIs and metadata and receives a generated client ID.
- **Redirect URI:** The exact client-controlled destination to which the browser returns an authorization code.
- **Resource indicator:** The exact protected API for which a token is requested, represented as a URL.
- **Scope:** A delegated permission on one token, such as `coinvault:sql:read` or `rag:documents:read`.

### 3.3 Credentials and transient state

- **Authorization transaction:** Short-lived state created when the client starts authorization. It binds client, redirect, state, PKCE challenge, requested scopes, and resource.
- **Consent session:** Short-lived state created after login. It binds the authenticated principal and maximum allowed scopes to the original request.
- **Authorization code:** Short-lived, single-use credential delivered through the browser.
- **PKCE verifier/challenge:** A client-held secret and its digest-like challenge. The code can be exchanged only by the client instance that proves the verifier.
- **Access token:** Short-lived bearer credential presented to a resource server.
- **Refresh token:** Longer-lived opaque credential used to obtain a new access token.
- **Refresh family:** The sequence of refresh tokens created by rotation. Reuse of an old generation revokes the family.

### 3.4 Discovery and MCP

The MCP 2025-11-25 authorization specification treats an MCP server as an OAuth resource server. The MCP endpoint advertises authorization servers through RFC 9728 Protected Resource Metadata. The client then discovers authorization endpoints through authorization-server metadata. The authorization server is related to MCP but is not part of MCP protocol dispatch.

This distinction drives the repository boundary:

- `oh-auth` owns issuance, grants, and generic verification;
- `go-go-mcp` owns MCP bearer enforcement, principal context, and tool scopes;
- the RAG server owns its HTTP middleware and document policy;
- each application owns its identity provider and scope projection.

## 4. Current CoinVault implementation

### 4.1 Construction

`coinvault/cmd/coinvault/cmds/mcp.go:127-173` currently:

- reads GEC and signing secrets;
- constructs `mcpauthz.GECClient`;
- opens `mcpoauth.Store`;
- loads signing and verification keys;
- constructs `mcpoauth.Provider`;
- passes it directly to `go-go-mcp` as an `embeddable.HTTPAuthProvider`.

This makes CoinVault's MCP command the composition root. That is appropriate, but the concrete provider currently depends directly on both CoinVault policy and go-go-mcp types.

### 4.2 Provider responsibilities

`coinvault/internal/mcpoauth/provider.go` is 761 lines. It owns:

- configuration and URL/key validation at lines 42-139;
- metadata and JWKS at lines 149-239;
- DCR at lines 255-313;
- authorization validation and transaction creation at lines 315-360;
- GEC callback and consent creation at lines 363-392;
- consent HTML and decisions at lines 395-449;
- code and refresh token exchange at lines 451-550;
- JWT signing at lines 553-572;
- revocation at lines 575-585;
- URL, PKCE, scope, random-secret, parsing, and error helpers at lines 587-761.

The code is functional, but its boundaries are application-shaped. `GECService`, GEC URLs, GEC principal fields, CoinVault scopes, CoinVault resource name, JWT employee claims, SQLite, HTTP, and MCP `AuthPrincipal` all meet in one type.

### 4.3 Persistence

`coinvault/internal/mcpoauth/store.go` defines:

- clients;
- authorization transactions;
- consent sessions;
- authorization codes;
- refresh grants;
- a SQLite schema;
- consume-once transitions;
- refresh rotation and family revocation.

Security-sensitive atomic operations already exist:

- authorization-code mismatch does not consume the code (`store.go:373-416`);
- refresh rotation consumes current and inserts successor in one transaction (`store.go:469-521`);
- refresh replay revokes the family (`store.go:437-450`, `469-492`);
- plaintext OAuth credentials are represented by SHA-256 digests in storage.

These behaviors should be preserved, then strengthened with the bounded lifecycle from `COINVAULT-OAUTH-STATE-LIFECYCLE`.

### 4.4 Identity and policy

`coinvault/internal/mcpauthz/gec_client.go` owns the GEC back channel and concrete `GECPrincipal`. `capabilities.go` owns CoinVault-specific scope projection. These are not reusable OAuth mechanics and should not move into generic packages.

### 4.5 MCP integration

`go-go-mcp/pkg/embeddable/auth_provider.go:15-34` defines `AuthPrincipal` and `HTTPAuthProvider`. `official_backend.go:292-394` mounts provider routes, serves resource metadata, extracts bearer tokens, validates them, and puts the principal into request context.

The final integration should be much narrower: go-go-mcp receives a verifier and metadata, not an entire application authorization server contract.

### 4.6 New repository state

`oh-auth` is currently an unnormalized Go template:

- `go.mod:1` still declares `github.com/go-go-golems/XXX`;
- `README.md` is template artwork;
- `cmd/XXX` and `pkg` are placeholders;
- `Makefile` and logcopter settings still reference `XXX`;
- no OAuth implementation or tests exist.

The repository is included in the workspace `go.work`, which is useful for extraction, but all final consumer validation must also run with `GOWORK=off` against declared module versions.

## 5. Problem statement and scope

### 5.1 Problem

CoinVault's OAuth implementation cannot be reused by a separate MCP server or RAG server without importing CoinVault internals and go-go-mcp. Copying it would create independent security behavior, migrations, token formats, and bug fixes.

The extraction must answer four questions cleanly:

1. What protocol and transition behavior is universal?
2. What identity and scope decisions remain application-owned?
3. What persistence operations must be atomic?
4. How do different resource servers consume tokens without depending on one another?

### 5.2 In scope

- authorization code flow for public clients;
- PKCE S256;
- DCR with bounded registration;
- authorization server metadata and JWKS;
- RFC 8707 resource indicators;
- explicit employee/user consent;
- JWT access tokens;
- opaque rotating refresh tokens;
- refresh revalidation and authoritative denial;
- token revocation;
- SQLite implementation and storage lifecycle;
- multiple exact resource URLs under one issuer;
- typed application principal attributes;
- adapters for browser identity, scope policy, claims, and audit;
- a neutral verified-token result for MCP and RAG adapters.

### 5.3 Out of scope for the first release

- confidential-client secrets;
- client credentials grant;
- device authorization grant;
- token exchange;
- social identity-provider implementation;
- user/account administration;
- hosted UI customization framework;
- distributed SQL or Redis stores;
- multi-tenant issuer routing;
- opaque access-token introspection;
- every optional DCR metadata field;
- preserving CoinVault's old internal Go API.

There will be a direct cutover. The repository guidelines explicitly reject unnecessary compatibility layers, and no public oh-auth API exists yet.

## 6. Design foundation: predictable transitions and composable parts

### 6.1 One operation, one state transition

Each engine method represents one meaningful protocol step:

```text
RegisterClient
BeginAuthorization
CompleteLogin
DecideConsent
ExchangeCode
Refresh
Revoke
VerifyAccessToken
```

An operation receives all caller data in one input value and returns one result value. It does not depend on package globals, ambient request state, or implicit mutable configuration.

This makes the implementation predictable: the same valid input and prior state produce the same decision, except for explicit dependencies such as time, random secrets, persistence, signing, and identity revalidation.

### 6.2 Separate decisions from effects

Pure decisions include:

- URL validation;
- scope normalization and intersection;
- PKCE verification;
- grant reduction;
- client trust presentation;
- token claim construction.

Effects include:

- reading the clock;
- generating a secret;
- writing SQLite;
- signing a JWT;
- calling an identity service;
- logging an audit event.

The engine receives each effect through a dependency. Tests can replace them without replacing business rules.

### 6.3 Authority only narrows

At initial consent, issued scopes must be contained in all four boundaries:

```text
requested by client
AND allowed for registered client
AND available to current principal for the selected resource
AND selected by the user on the consent screen
```

During refresh, the next scopes must be contained in both:

```text
current refresh grant
AND scopes currently available to the revalidated principal
```

An application policy returns available scopes; it never returns a final token grant. The engine always performs the intersection. This preserves the safety rule under every adapter composition.

### 6.4 Invalid states should be hard to construct

Use validated named values instead of passing raw strings everywhere:

```go
type ClientID string
type Subject string
type Scope string
type ResourceID string
type RedirectURI string
type TransactionToken string
type ConsentToken string
```

Construct URLs, scope sets, PKCE values, and configuration through validation functions. Store records can still be decoded from a database, but decoding must validate them before the engine sees them.

### 6.5 Expected decisions are data, not generic errors

An ineligible principal is an expected policy result. A GEC timeout is an operational error. Represent the difference explicitly:

```go
type RevalidationStatus uint8

const (
    RevalidationUnknown RevalidationStatus = iota
    RevalidationEligible
    RevalidationIneligible
)

type Revalidation[A any] struct {
    Status    RevalidationStatus
    Principal Principal[A]
}
```

Non-nil errors mean the system could not obtain a trustworthy decision. `Unknown` prevents a zero-value result from becoming an accidental denial.

### 6.6 Composition occurs through narrow capabilities

The engine depends on independent interfaces:

- `Store[A]` can persist transitions;
- `ScopePolicy[A]` computes current available scopes;
- `PrincipalRevalidator[A]` rechecks a subject;
- `TokenService[A]` issues and verifies access tokens;
- `SecretSource` produces opaque credentials;
- `Clock` supplies time;
- `AuditSink` receives redacted events.

A consumer can replace one capability without reimplementing OAuth.

## 7. Target package structure

```text
oh-auth/
  pkg/
    oauthserver/
      config.go
      identifiers.go
      principal.go
      scopes.go
      clients.go
      grants.go
      transitions.go
      engine.go
      errors.go
      ports.go
      metadata.go
      consent.go
      lifecycle.go

      httptransport/
        server.go
        metadata.go
        registration.go
        authorization.go
        consent.go
        token.go
        revoke.go
        errors.go
        default_consent.html

      jwttokens/
        service.go
        claims.go
        keys.go
        jwks.go

      sqlitestore/
        open.go
        schema.go
        migrations.go
        clients.go
        transactions.go
        consent.go
        codes.go
        refresh.go
        prune.go

      memorytest/
        store.go
        identity.go
        clock.go
        secrets.go

    oauthresource/
      token.go
      metadata.go
      challenge.go

  examples/
    minimal-server/
    multi-resource/
    external-login/

  ttmp/
```

Dependency direction:

```text
                 application identity + policy
                           |
                           v
httptransport ------> oauthserver <------ sqlitestore
      |                    ^                    |
      |                    |                    |
      +-------------- jwttokens ---------------+
                           |
                           v
                     oauthresource
                           |
                 +---------+---------+
                 |                   |
             MCP adapter         RAG adapter
```

Rules:

- `oauthserver` imports only standard-library packages where practical.
- `sqlitestore`, `jwttokens`, and `httptransport` import `oauthserver`.
- `oauthserver` never imports its adapters.
- `oh-auth` never imports CoinVault or go-go-mcp.
- go-go-mcp and RAG applications import oh-auth at their integration edges.

## 8. Core type model

### 8.1 Resource registry

One issuer may serve multiple resource servers:

```go
type Resource struct {
    ID              ResourceID
    DisplayName     string
    SupportedScopes ScopeSet
}

type ResourceRegistry interface {
    LookupResource(ctx context.Context, id ResourceID) (Resource, error)
    ListResources(ctx context.Context) ([]Resource, error)
}
```

Every transaction, code, refresh grant, and access token carries exactly one `ResourceID`. The access token audience must equal it.

The first implementation can use an immutable in-memory registry built from validated configuration.

### 8.2 Canonical scope set

Do not expose mutable map internals:

```go
type ScopeSet struct {
    values []Scope
}

func NewScopeSet(values ...Scope) (ScopeSet, error)
func ParseScopes(raw string) (ScopeSet, error)
func (s ScopeSet) Contains(scope Scope) bool
func (s ScopeSet) Values() []Scope
func (s ScopeSet) Intersect(other ScopeSet) ScopeSet
func (s ScopeSet) IsSubsetOf(other ScopeSet) bool
func (s ScopeSet) String() string
```

Construction trims, validates, deduplicates, and sorts. `Values` returns a copy. This gives deterministic tokens, tests, and metadata.

### 8.3 Typed application principal

Use one generic parameter for application-specific principal attributes:

```go
type Principal[A any] struct {
    Subject              Subject
    DisplayName          string
    Email                string
    AuthorizationVersion int64
    Attributes           A
}
```

Examples:

```go
type GECAttributes struct {
    EmployeeID   int64
    Capabilities []string
}

type RAGAttributes struct {
    OrganizationID string
    DocumentRoles  []string
}
```

The generic parameter avoids `map[string]any` in authorization policy. The stable OAuth-facing fields remain consistent across applications.

Persistence receives a codec:

```go
type PrincipalCodec[A any] interface {
    EncodePrincipal(Principal[A]) ([]byte, error)
    DecodePrincipal([]byte) (Principal[A], error)
}
```

The default JSON codec can use `encoding/json`. Consumers may supply a versioned codec when long-lived refresh grants require schema evolution.

### 8.4 Client and trust

```go
type ClientTrust string

const (
    ClientTrustUnverified ClientTrust = "unverified"
    ClientTrustConfigured ClientTrust = "configured"
)

type Client struct {
    ID            ClientID
    DisplayName   string
    Trust         ClientTrust
    RedirectURIs  []RedirectURI
    AllowedScopes ScopeSet
    CreatedAt     time.Time
    LastUsedAt    time.Time
}
```

Public DCR can create only unverified clients. Configured trust requires an application-owned provisioning path.

### 8.5 Stored states

```go
type AuthorizationTransaction struct {
    Token           TransactionToken
    ClientID        ClientID
    RedirectURI     RedirectURI
    State           string
    PKCEChallenge   PKCEChallenge
    RequestedScopes ScopeSet
    Resource        ResourceID
    ExpiresAt       time.Time
}

type ConsentSession[A any] struct {
    Token         ConsentToken
    Client        ConsentClientSnapshot
    State         string
    PKCEChallenge PKCEChallenge
    Principal     Principal[A]
    AllowedScopes ScopeSet
    Resource      ResourceID
    ExpiresAt     time.Time
}

type AuthorizationCodeRecord[A any] struct {
    Digest        CredentialDigest
    ClientID      ClientID
    RedirectURI   RedirectURI
    PKCEChallenge PKCEChallenge
    Principal     Principal[A]
    Scopes        ScopeSet
    Resource      ResourceID
    ExpiresAt     time.Time
}

type RefreshGrant[A any] struct {
    Digest     CredentialDigest
    FamilyID   RefreshFamilyID
    Generation uint64
    ClientID   ClientID
    Principal  Principal[A]
    Scopes     ScopeSet
    Resource   ResourceID
    ExpiresAt  time.Time
}
```

Raw authorization codes and refresh tokens exist only in engine result values and HTTP responses. Stores receive digests.

## 9. Engine dependencies and construction

```go
type Dependencies[A any] struct {
    Store       Store[A]
    Resources   ResourceRegistry
    Scopes      ScopePolicy[A]
    Revalidator PrincipalRevalidator[A]
    Tokens      TokenService[A]
    Secrets     SecretSource
    Clock       Clock
    Audit       AuditSink
}

type Engine[A any] struct {
    config Config
    deps   Dependencies[A]
}

func New[A any](cfg Config, deps Dependencies[A]) (*Engine[A], error)
```

`New` validates everything once:

- issuer is a public origin;
- resources are absolute HTTPS URLs except loopback development;
- TTLs and capacities are positive and internally sensible;
- every required dependency is present;
- signing service advertises compatible issuer and algorithms;
- supported scopes and reserved claims do not conflict.

Avoid functional options for required dependencies. A struct makes missing capabilities visible in code review. Optional behavior belongs in explicit configuration fields with secure defaults.

### 9.1 Clock and secret source

```go
type Clock interface {
    Now() time.Time
}

type SecretSource interface {
    NewTransactionToken() (TransactionToken, error)
    NewConsentToken() (ConsentToken, error)
    NewAuthorizationCode() (AuthorizationCode, error)
    NewRefreshToken() (RefreshToken, error)
    NewRefreshFamilyID() (RefreshFamilyID, error)
    NewTokenID() (string, error)
}
```

Production uses `crypto/rand`. Tests use deterministic, collision-free fixtures. No default may use `math/rand`.

### 9.2 Scope policy

```go
type ScopePolicy[A any] interface {
    AvailableScopes(
        ctx context.Context,
        principal Principal[A],
        resource Resource,
    ) (ScopeSet, error)
}
```

The engine computes the actual grant. The policy cannot bypass client, request, consent, or previous-grant boundaries.

### 9.3 Principal revalidation

```go
type PrincipalRevalidator[A any] interface {
    Revalidate(
        ctx context.Context,
        subject Subject,
    ) (Revalidation[A], error)
}
```

Semantics:

- `Eligible`: use returned current principal;
- `Ineligible`: revoke refresh family;
- non-nil error: issue nothing, preserve grant, return retryable failure;
- `Unknown`: fail closed and preserve grant.

### 9.4 Audit sink

```go
type AuditEvent struct {
    Time       time.Time
    Operation  string
    Outcome    string
    Subject    Subject
    ClientID   ClientID
    Resource   ResourceID
    Scopes     ScopeSet
    ReasonCode string
}

type AuditSink interface {
    Record(context.Context, AuditEvent)
}
```

Audit delivery should not hold plaintext credentials or request bodies. The first implementation may provide a no-op sink and synchronous best-effort structured logger. Do not make token issuance depend on an external audit network service.

## 10. Transition API

### 10.1 Register client

```go
type RegisterClientInput struct {
    DisplayName   string
    RedirectURIs  []string
    RequestedScopes []string
}

type RegisterClientResult struct {
    Client Client
}

func (e *Engine[A]) RegisterClient(
    ctx context.Context,
    in RegisterClientInput,
) (RegisterClientResult, error)
```

The engine validates metadata limits, URLs, supported scopes, trust, and capacity before persistence. DCR always sets `ClientTrustUnverified`.

### 10.2 Begin authorization

```go
type BeginAuthorizationInput struct {
    ClientID      string
    RedirectURI   string
    ResponseType  string
    State         string
    CodeChallenge string
    ChallengeMethod string
    Scopes        []string
    Resource      string
}

type BeginAuthorizationResult struct {
    Transaction TransactionToken
    LoginContext LoginContext
}
```

The result gives the application identity adapter what it needs to start browser login. The HTTP transport asks `LoginStarter` for the actual redirect URL.

```go
type LoginStarter interface {
    AuthorizationURL(
        ctx context.Context,
        login LoginContext,
    ) (string, error)
}
```

### 10.3 Complete login

The identity callback is application-specific. Its handler exchanges GEC, OIDC, SAML, or another assertion and then calls:

```go
type CompleteLoginInput[A any] struct {
    Transaction TransactionToken
    Principal   Principal[A]
}

type CompleteLoginResult struct {
    ConsentToken ConsentToken
    ConsentURL   string
}

func (e *Engine[A]) CompleteLogin(
    ctx context.Context,
    in CompleteLoginInput[A],
) (CompleteLoginResult, error)
```

The engine:

1. loads the pending transaction;
2. reloads and validates the client;
3. looks up the resource;
4. asks `ScopePolicy` for current available scopes;
5. intersects request, client, resource, and principal scopes;
6. snapshots client name, trust, redirect origin, and exact redirect;
7. atomically consumes the transaction and creates consent.

### 10.4 Render and decide consent

```go
type ConsentView struct {
    Token             ConsentToken
    ResourceName      string
    PrincipalName     string
    PrincipalEmail    string
    ClientName        string
    ClientTrust       ClientTrust
    RedirectOrigin    string
    RedirectURI       string
    AccessTokenTTL    time.Duration
    AuthorizationEnds time.Time
    Scopes            []ConsentScope
}

func (e *Engine[A]) ConsentView(
    ctx context.Context,
    token ConsentToken,
) (ConsentView, error)

type ConsentDecision uint8

const (
    ConsentDecisionUnknown ConsentDecision = iota
    ConsentDecisionApprove
    ConsentDecisionDeny
)

type DecideConsentInput struct {
    Token          ConsentToken
    Decision       ConsentDecision
    SelectedScopes []Scope
}

type DecideConsentResult struct {
    RedirectURI string
}
```

On approval, the engine generates a code, intersects selected scopes with allowed scopes, and asks the store to consume consent and create the code in one transaction. On denial, it consumes consent and produces an `access_denied` redirect. Posted client or redirect metadata is ignored. The unguessable, expiring, one-time consent token rendered into the no-store form is also the synchronizer CSRF token; missing, wrong, expired, and replayed values are rejected. No additional browser session or cookie subsystem is required for v0.1.

### 10.5 Exchange authorization code

```go
type ExchangeCodeInput struct {
    Code         string
    ClientID     string
    RedirectURI  string
    CodeVerifier string
}

type TokenResponse struct {
    AccessToken  string
    TokenType    string
    ExpiresIn    time.Duration
    RefreshToken string
    Scopes       ScopeSet
}
```

Safe sequence:

```text
load code without consuming
  -> validate client + redirect + PKCE + expiry
  -> prepare access token and optional refresh successor
  -> atomically consume code and create refresh grant
  -> return prepared credentials
```

A mismatched attempt does not consume the code. If signing or secret generation fails, the code remains usable. If two correct exchanges race, exactly one commit succeeds.

### 10.6 Refresh

```go
type RefreshInput struct {
    RefreshToken string
    ClientID     string
}

func (e *Engine[A]) Refresh(
    ctx context.Context,
    in RefreshInput,
) (TokenResponse, error)
```

Safe sequence:

```text
load current refresh grant
  -> bind client
  -> revalidate subject
       ineligible: revoke family, invalid_grant
       operational error: preserve current, retryable error
       eligible: continue
  -> compute nextScopes = currentScopes intersect availableScopes
  -> prepare access token + successor refresh token
  -> atomically consume current and insert successor
  -> return credentials
```

Capability expansion cannot add scopes because the previous grant remains an upper bound.

### 10.7 Revoke

```go
type RevokeInput struct {
    Token    string
    ClientID string
}

func (e *Engine[A]) Revoke(ctx context.Context, in RevokeInput) error
```

The externally observable endpoint remains idempotent and does not reveal whether a token existed. Internally it revokes the matching family when client binding succeeds.

## 11. Store API: transitions, not generic CRUD

A generic repository with `Create`, `Update`, and `Delete` would let callers bypass security invariants. Define operations around state transitions.

```go
type Store[A any] interface {
    RegisterClient(
        context.Context,
        Client,
        StatePolicy,
    ) error

    GetClient(context.Context, ClientID) (Client, error)
    TouchClient(context.Context, ClientID, time.Time) error

    CreateAuthorization(
        context.Context,
        AuthorizationTransaction,
        StatePolicy,
    ) error

    GetAuthorization(
        context.Context,
        CredentialDigest,
    ) (AuthorizationTransaction, error)

    CommitLogin(
        context.Context,
        LoginCommit[A],
        StatePolicy,
    ) error

    GetConsent(
        context.Context,
        CredentialDigest,
    ) (ConsentSession[A], error)

    CommitConsent(
        context.Context,
        ConsentCommit[A],
        StatePolicy,
    ) (ConsentCommitResult, error)

    GetCodeForExchange(
        context.Context,
        CodeExchangeBinding,
    ) (AuthorizationCodeRecord[A], error)

    CommitCodeExchange(
        context.Context,
        CodeExchangeCommit[A],
        StatePolicy,
    ) error

    GetRefreshGrant(
        context.Context,
        CredentialDigest,
    ) (RefreshGrant[A], error)

    CommitRefreshRotation(
        context.Context,
        RefreshRotation[A],
        StatePolicy,
    ) error

    RevokeRefreshFamily(
        context.Context,
        RefreshFamilyID,
        time.Time,
    ) error

    Prune(context.Context, StatePolicy) (PruneStats, error)
    Counts(context.Context) (StateCounts, error)
}
```

Every commit method must recheck the expected prior state inside its transaction. A prior read is advisory; the commit is authoritative.

### 11.1 Store errors

```go
var (
    ErrNotFound      = errors.New("oauth record not found")
    ErrConsumed      = errors.New("oauth credential consumed")
    ErrExpired       = errors.New("oauth credential expired")
    ErrRevoked       = errors.New("oauth grant revoked")
    ErrConflict      = errors.New("oauth transition conflict")
    ErrCapacity      = errors.New("oauth state capacity reached")
    ErrBinding       = errors.New("oauth credential binding mismatch")
)
```

Engine code maps these errors to safe OAuth outcomes. SQL errors remain wrapped causes, not protocol strings.

## 12. SQLite design

### 12.1 Driver and construction

Use a pure-Go SQLite driver in `sqlitestore` so consumers do not require CGo. Open the database with explicit pragmas after connection rather than relying on driver-specific DSN syntax:

- foreign keys on;
- WAL mode;
- busy timeout;
- one writer-oriented connection pool initially.

```go
func Open[A any](
    ctx context.Context,
    path string,
    codec oauthserver.PrincipalCodec[A],
    options ...OpenOption,
) (*Store[A], error)
```

The core `oauthserver` package does not import SQLite.

### 12.2 Schema principles

- store only SHA-256 digests of transaction, consent, code, and refresh credentials;
- store principal snapshots with a codec/version field;
- retain exact client, redirect, resource, scope, and PKCE bindings;
- index expiry, terminal timestamps, family ID, client ID, and last activity;
- use additive numbered migrations owned by oh-auth;
- never parse migration errors by broad string matching when a schema-version table can make intent explicit.

### 12.3 Lifecycle and quotas

Adopt the bounded state policy designed in `COINVAULT-OAUTH-STATE-LIFECYCLE`:

```go
type StatePolicy struct {
    Registration RegistrationPolicy
    Capacity     StateCapacity
    Retention    RetentionPolicy
}
```

Prune child rows before clients. Keep all used refresh-token digests until family expiry so replay detection remains effective. Admission performs prune, count, expected-state check, and insert in one transaction.

### 12.4 Migration from CoinVault

CoinVault's current SQLite database can be migrated because SQLite file format is driver-independent. However, do not make legacy schema support a permanent public feature.

Pragmatic cutover options:

1. For development, deploy a fresh oh-auth database and require clients to relink.
2. If preserving current refresh grants is required, write a one-time migration command under the ticket and remove it after production cutover.

Per repository guidance, do not ship a standing compatibility layer without explicit approval.

## 13. JWT token service and resource-server API

### 13.1 Token service

```go
type TokenService[A any] interface {
    IssueAccessToken(
        context.Context,
        AccessGrant[A],
    ) (IssuedAccessToken, error)

    VerifyAccessToken(
        context.Context,
        string,
        ResourceID,
    ) (VerifiedAccessToken, error)

    JWKS(context.Context) (JWKS, error)
}
```

The implementation owns reserved claims:

- `iss`;
- `sub`;
- `aud`;
- `iat`;
- `nbf`;
- `exp`;
- `jti`;
- `client_id`;
- `scope`;
- the configured access-token `typ`.

Application claim enrichment is restricted:

```go
type ClaimProvider[A any] interface {
    ExtraClaims(
        context.Context,
        Principal[A],
    ) (map[string]any, error)
}
```

The JWT service rejects attempts to overwrite reserved names. CoinVault may add `gec_employee_id` and `gec_authorization_version`; a RAG server may add an organization identifier. Verification uses a fixed algorithm/key-type allowlist and issuer-configured key ring. It rejects `alg=none`, the wrong token type, and attacker-selected `jwk`, `jku`, `x5u`, or certificate material from JWT headers. `kid` only selects among keys already trusted for the configured issuer.

### 13.2 Verified token

```go
type VerifiedAccessToken struct {
    Subject    Subject
    ClientID   ClientID
    Issuer     string
    Resource   ResourceID
    Scopes     ScopeSet
    IssuedAt   time.Time
    ExpiresAt  time.Time
    TokenID    string
    ExtraClaims map[string]any
}
```

This type is independent of MCP. A go-go-mcp adapter translates it into `embeddable.AuthPrincipal`; a RAG middleware translates it into its request principal.

### 13.3 Key rotation

Configuration supports one active signing key and multiple verification-only keys. JWKS publishes all current verification keys. New tokens use only the active key. Remove an old key only after every token signed by it has expired.

Private-key file loading is an application/deployment concern. `jwttokens` should accept parsed keys or a signer interface; optional helper functions may parse PEM without reading arbitrary filesystem paths.

## 14. HTTP transport

### 14.1 Standard routes

`httptransport.Server[A]` mounts:

```text
GET  /.well-known/oauth-authorization-server
GET  /.well-known/openid-configuration
GET  /jwks.json
POST /oauth/register
GET  /oauth/authorize
GET  /oauth/consent
POST /oauth/consent
POST /oauth/token
POST /oauth/revoke
```

The application mounts its identity callback with a helper:

```go
type CallbackAuthenticator[A any] interface {
    AuthenticateCallback(
        context.Context,
        *http.Request,
    ) (TransactionToken, Principal[A], error)
}

func (s *Server[A]) IdentityCallbackHandler(
    authenticator CallbackAuthenticator[A],
) http.Handler
```

This keeps GEC, OIDC, or SAML parsing outside generic OAuth logic while reusing completion and error behavior.

### 14.2 HTTP handlers stay thin

A handler should do only:

1. allow only the endpoint's exact HTTP methods and content types;
2. apply body, field, array, query-count, header, and bearer-token size limits;
3. parse protocol fields with one strict decoder and reject trailing data;
4. call one engine method;
5. map a typed result or typed error to HTTP;
6. set no-store and security headers.

Unexpected methods return 405, unsupported media types return 415, and oversized requests return 413. CORS is absent by default. The application configures HTTP server deadlines, and identity/back-channel clients use explicit timeouts. Existing registration/state caps remain the durable resource-exhaustion control.

It must not directly query SQLite or compute final grants.

### 14.3 OAuth errors

Use a typed error with safe client text and wrapped internal cause:

```go
type ErrorCode string

const (
    ErrorInvalidRequest        ErrorCode = "invalid_request"
    ErrorInvalidClientMetadata ErrorCode = "invalid_client_metadata"
    ErrorInvalidRedirectURI    ErrorCode = "invalid_redirect_uri"
    ErrorInvalidScope          ErrorCode = "invalid_scope"
    ErrorInvalidTarget         ErrorCode = "invalid_target"
    ErrorAccessDenied          ErrorCode = "access_denied"
    ErrorInvalidGrant          ErrorCode = "invalid_grant"
    ErrorUnsupportedGrant      ErrorCode = "unsupported_grant_type"
    ErrorTemporary             ErrorCode = "temporarily_unavailable"
)

type OAuthError struct {
    Code            ErrorCode
    SafeDescription string
    HTTPStatus      int
    Cause           error
}
```

Logs may include `Cause`; HTTP receives only safe fields.

### 14.4 Consent UI

The default consent page must always show:

- resource name;
- principal name/email;
- client display name;
- unverified/configured trust wording;
- redirect origin;
- exact redirect URI as non-clickable text;
- selectable scopes;
- approve and deny actions.

Use `html/template`, no remote scripts/styles/images, and `Cache-Control: no-store`. First release permits branding strings and local CSS only, not an arbitrary renderer that can omit mandatory security fields. Also show access-token lifetime and the absolute offline authorization expiry.

The minimal browser hardening is:

```text
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
```

This prevents clickjacking and consent-token referrer leakage without introducing a new browser-session abstraction.

## 15. Resource-server integration

### 15.1 Neutral interface

`pkg/oauthresource` defines protocol-neutral data and helpers:

```go
type Verifier interface {
    VerifyAccessToken(
        context.Context,
        string,
        oauthserver.ResourceID,
    ) (oauthserver.VerifiedAccessToken, error)
}

type Metadata struct {
    Resource             string   `json:"resource"`
    AuthorizationServers []string `json:"authorization_servers"`
    ScopesSupported      []string `json:"scopes_supported,omitempty"`
    ResourceName         string   `json:"resource_name,omitempty"`
}

func BearerChallenge(metadataURL string) string
```

It should not own MCP tool authorization or RAG document authorization.

### 15.2 MCP adapter

The adapter belongs in go-go-mcp or the MCP application because dependency direction should be:

```text
go-go-mcp -> oh-auth
```

not:

```text
oh-auth -> go-go-mcp
```

The adapter maps:

```go
VerifiedAccessToken -> embeddable.AuthPrincipal
```

and supplies protected-resource metadata and `WWW-Authenticate`. Long term, go-go-mcp's provider interface can be narrowed from route mounting plus validation to verifier plus metadata; the authorization server routes can be mounted separately by the composition root.

### 15.3 RAG adapter

A normal RAG HTTP service can use middleware that:

1. extracts the bearer header;
2. verifies fixed algorithm/type, issuer, time, and exact audience equal to its resource URL;
3. checks route-required scopes;
4. stores `VerifiedAccessToken` in context;
5. derives application document filters from trusted token claims and server policy.

Protected operations are deny-by-default and authorization runs on every request. Consumer startup/conformance tests should fail when a protected route or MCP tool lacks an explicit policy. UI visibility and model arguments never count as enforcement.

Model arguments must never select authorization scopes or principal attributes.

### 15.4 Shared issuer, distinct resources

Example:

```text
issuer:   https://auth.example.com
MCP:      https://mcp.example.com/mcp
RAG API:  https://rag.example.com/api
```

An access token for MCP must fail at RAG because `aud` differs. Refresh grants remain bound to their original resource. A client requests a separate authorization grant for a different resource.

## 16. Configuration model

```go
type Config struct {
    Issuer        string
    Resources     []ResourceConfig
    SupportedScopes ScopeSet

    AccessTTL      time.Duration
    RefreshTTL     time.Duration
    TransactionTTL time.Duration
    ConsentTTL     time.Duration
    CodeTTL        time.Duration

    StatePolicy StatePolicy
    HTTP        HTTPPolicy
}
```

Secure defaults:

- access token: 10 minutes;
- refresh: 30 days;
- transaction: 5 minutes;
- consent: 10 minutes;
- code: 1 minute;
- public clients only;
- PKCE S256 mandatory;
- HTTPS except loopback development;
- exact resource and redirect matching;
- bounded registration and state;
- no dev/static token feature in production library.

The library accepts values. Applications decide whether they came from Glazed, environment, Vault, files, or another configuration source.

## 17. Decision records

### Decision: build a protocol-neutral OAuth library

- **Context:** MCP and RAG servers need the same authorization behavior but have different request and policy layers.
- **Options considered:** keep OAuth in CoinVault; move it into go-go-mcp; create `oh-auth` independent of both.
- **Decision:** Implement issuance and verification in `oh-auth` with no MCP or CoinVault dependency.
- **Rationale:** OAuth roles and grants are independent of MCP tool dispatch and RAG retrieval.
- **Consequences:** Small adapters are required in each consumer, but security behavior has one source of truth.
- **Status:** proposed

### Decision: model public operations as explicit transitions

- **Context:** Generic CRUD permits invalid partial changes and obscures one-time credential semantics.
- **Options considered:** repository CRUD; HTTP handlers owning transactions; transition-oriented engine/store methods.
- **Decision:** Expose named protocol operations and atomic store commits.
- **Rationale:** Each security invariant has one implementation and one test boundary.
- **Consequences:** Store interfaces are larger but semantically precise.
- **Status:** proposed

### Decision: use a typed principal attribute parameter

- **Context:** CoinVault and RAG need different policy data; `map[string]any` spreads runtime assertions through security code.
- **Options considered:** fixed universal principal; opaque JSON; generic `Principal[A]`.
- **Decision:** Use one generic attribute type while keeping common OAuth identity fields fixed.
- **Rationale:** Consumers get compile-time policy types without forcing GEC fields into the library.
- **Consequences:** Store, engine, and adapters are generic and SQLite requires a codec.
- **Status:** proposed

### Decision: the engine owns grant intersection

- **Context:** A consumer-provided policy could accidentally return scopes broader than request or consent.
- **Options considered:** let policy return final grants; validate policy output informally; centralize intersection.
- **Decision:** Policy returns available scopes; engine computes every final grant.
- **Rationale:** Composition cannot bypass authority boundaries.
- **Consequences:** Applications express implication in available scopes but cannot override final reduction.
- **Status:** proposed

### Decision: support multiple exact resources

- **Context:** Separate MCP and RAG servers need distinct token audiences under one issuer.
- **Options considered:** one resource per engine; arbitrary audiences; validated resource registry.
- **Decision:** Configure a finite resource registry and bind every grant to one exact resource.
- **Rationale:** Reuse does not require duplicate issuers, and tokens cannot cross services.
- **Consequences:** Scope policy and metadata are resource-aware.
- **Status:** proposed

### Decision: keep identity callbacks application-owned

- **Context:** GEC, OIDC, SAML, and future login systems have different callback data and security contracts.
- **Options considered:** generic callback maps; identity-specific code in core; callback authenticator interface.
- **Decision:** Application adapter authenticates callback and gives the engine a typed principal plus transaction token.
- **Rationale:** Core OAuth state remains stable while identity protocols vary.
- **Consequences:** Each application mounts one small callback adapter.
- **Status:** proposed

### Decision: use pure-Go SQLite initially

- **Context:** A reusable library should work in minimal server containers without CGo while retaining CoinVault's durable semantics.
- **Options considered:** mattn/go-sqlite3; modernc SQLite; no default store.
- **Decision:** Implement a pure-Go SQLite adapter and keep it behind `Store[A]`.
- **Rationale:** Portable deployment and one maintained default.
- **Consequences:** Migration and concurrency behavior must be tested against the actual chosen driver.
- **Status:** proposed

### Decision: direct cutover, no compatibility API

- **Context:** oh-auth has no released API and repository guidance rejects unnecessary compatibility layers.
- **Options considered:** preserve `mcpoauth.Provider`; adapter aliases; migrate consumers directly.
- **Decision:** Define the target API and cut consumers over once conformance tests pass.
- **Rationale:** Avoid freezing CoinVault coupling into a new library.
- **Consequences:** Extraction should happen on coordinated branches and old code is deleted after cutover.
- **Status:** proposed

## 18. Detailed implementation plan

### Phase 0: normalize the repository

Files:

- `go.mod` — change module to `github.com/go-go-golems/oh-auth` while preserving the user's current toolchain choice;
- `README.md` — replace template text with library purpose and security status;
- `Makefile`, `.goreleaser.yaml`, workflows, and logcopter config — remove `XXX` placeholders;
- remove `cmd/XXX` unless a concrete example/maintenance CLI is needed;
- replace placeholder `pkg` package with real packages;
- retain docmgr ticket and repository quality tooling.

Commands:

```bash
GOWORK=off go mod tidy
GOWORK=off go test ./...
make ci-check
```

### Phase 1: implement value types and pure rules

Create:

- identifiers and URL constructors;
- `ScopeSet`;
- PKCE S256 validation;
- client trust and consent snapshots;
- principal and resource types;
- typed OAuth errors;
- state policies and default validation.

Port tests before handlers. Add fuzz tests for URL parsing, scope normalization, and PKCE syntax.

### Phase 2: define transition fixtures and ports

Create interfaces for store, policy, revalidator, token service, clock, secrets, and audit. Build deterministic test implementations in `memorytest`.

Write engine-level scenario tests with no HTTP or SQLite:

```text
register -> authorize -> login -> consent -> code -> token -> refresh -> revoke
```

Also write denial, mismatch, expiry, replay, transient revalidation, and multi-resource scenarios.

### Phase 3: implement SQLite from store conformance tests

1. Copy behavior, not concrete types, from CoinVault store tests.
2. Create explicit schema-version migrations.
3. Add digest-only credentials and principal codec/version.
4. Implement one transition at a time.
5. Add bounded admission and pruning before production integration.
6. Run race and concurrent-final-slot tests.

A shared conformance suite should run against both the deterministic memory store and SQLite.

### Phase 4: implement JWT tokens

1. Define reserved claims, fixed access-token type, and verified token result.
2. Implement RS256 signing and exact issuer/audience validation with a fixed algorithm/key-type allowlist.
3. Add claim-provider reserved-name rejection and reject token-supplied key material.
4. Publish deterministic JWKS ordering.
5. Test active plus overlap verification keys.
6. Test `alg=none`, wrong algorithm/type/key ID, attacker key headers, issuer, audience, expiry, missing claims, and extra claims.

### Phase 5: implement engine transitions

Implement in flow order:

1. `RegisterClient`.
2. `BeginAuthorization`.
3. `CompleteLogin`.
4. `ConsentView` and `DecideConsent`.
5. `ExchangeCode`.
6. `Refresh`.
7. `Revoke`.

For each operation:

- define input/result;
- write happy and failure tests;
- implement pure validation;
- implement atomic store commit;
- audit safe outcome;
- document mutation ordering.

### Phase 6: implement HTTP transport

Add metadata, DCR, authorization, consent, token, and revocation handlers. Add the identity callback helper and secure default consent page.

Implement exact methods/content types, the consent token's CSRF semantics, anti-framing CSP, no-referrer, no-store, nosniff, no default CORS, size limits, and documented HTTP/back-channel deadlines.

Protocol tests should use `httptest.Server` and one client with redirects disabled. Validate headers, status, JSON shape, redirects, consent-token failure/replay, framing defenses, no-store, body bounds, methods/content types, and exact OAuth errors.

### Phase 7: implement the three review hardenings in the library

Do not extract known defects and fix them later. Before CoinVault cutover, complete:

- unverified client identity and exact redirect disclosure;
- explicit eligible/ineligible/transient refresh outcomes;
- registration and all-table lifecycle bounds.

The three CoinVault design tickets are source specifications, but oh-auth becomes the implementation source of truth.

### Phase 8: build CoinVault adapters

CoinVault retains:

- `GECAttributes`;
- GEC assertion/callback and revalidation client;
- capability-to-scope policy;
- employee JWT extra claims;
- secret and runtime configuration;
- MCP tool scope policy.

CoinVault imports oh-auth and constructs `Engine[GECAttributes]`, SQLite, JWT, and HTTP server. Its GEC callback uses `IdentityCallbackHandler`.

### Phase 9: cut over go-go-mcp integration

Add a small adapter that maps `VerifiedAccessToken` to `embeddable.AuthPrincipal`. Keep bearer extraction and principal context in go-go-mcp. Mount authorization-server routes in the application composition root rather than requiring the MCP provider to own them.

Run `GOWORK=off` against a published oh-auth version before declaring extraction complete.

### Phase 10: add a RAG consumer

Create or integrate a RAG resource server with a distinct resource URL and scopes. Prove through deterministic local/integration tests—not a deployed smoke run at this phase—that:

- MCP token is rejected by RAG audience checks;
- RAG token is rejected by MCP audience checks;
- the same principal can authorize each independently;
- refresh remains resource-bound;
- application document policy derives only from verified identity and scopes.

### Phase 11: remove duplicate code and prepare release

Delete CoinVault's generic provider/store/token helpers after cutover. Retain only adapters and application policy. Search for duplicate PKCE, scope, JWT, DCR, and refresh implementations.

Prepare a release candidate only after:

- store and HTTP conformance pass;
- CoinVault passes outside `go.work`;
- one RAG consumer passes deterministic integration tests;
- focused security tests are complete;
- API docs and examples compile.

Do not run a deployed smoke after each phase or adapter change. Local unit, conformance, and integration tests are the development loop.

### Phase 12: run one consolidated final smoke and release

Run exactly one deployed smoke after the release candidate is published and the authorization server plus MCP/RAG consumers are deployed. Expose it through one command:

```bash
make smoke-final SMOKE_CONFIG=/secure/path/smoke.yaml
```

The target invokes one orchestrator and produces one redacted JSON/Markdown summary. It may pause for the minimum human browser login/consent interaction, but it must not persist access tokens, refresh tokens, authorization codes, cookies, or service credentials in logs/artifacts.

The single smoke performs:

1. check authorization-server, MCP, and RAG health endpoints;
2. fetch authorization-server metadata, JWKS, and each resource's protected-resource metadata;
3. confirm one unauthenticated protected request returns 401 with the expected challenge;
4. dynamically register one disposable public client;
5. complete one authorization-code + PKCE flow for MCP;
6. call one inexpensive read-only MCP operation;
7. refresh the MCP grant once and use the replacement access token once;
8. complete one authorization-code + PKCE flow for the distinct RAG resource;
9. call one inexpensive read-only RAG operation;
10. present one resource's token to the other resource and confirm rejection;
11. emit a pass/fail summary and discard all local credentials.

The smoke deliberately excludes refresh replay, revocation, capability mutation, key rotation, expiry waiting, rate/capacity exhaustion, concurrent races, upstream outage injection, and the exhaustive OWASP matrix. Those remain deterministic integration, security, operational, or manual release tests. Use disposable grants if a future smoke step becomes destructive.

Tag/release only after this one smoke passes.

## 19. Testing strategy

The development loop uses fast deterministic tests. It does **not** run deployed smoke tests after phases, commits, or ordinary refactors. All protocol negatives, races, expiry, replay, cleanup, and upstream failures use `httptest`, injected clocks, fake identity providers, and temporary SQLite databases. The only deployed smoke is Phase 12 after release-candidate deployment.

### 19.1 Pure rule tests

- scope sets are sorted, unique, immutable from caller mutation, and correctly intersected;
- grant scopes never exceed any authority boundary;
- refresh never expands scopes;
- resource/redirect URLs are exact and safely validated;
- PKCE challenge computation matches known vectors;
- unverified trust cannot be upgraded by DCR input.

### 19.2 Transition sequence tests

Use a small model that tracks the expected stage of each credential. Generate valid and invalid operation sequences such as:

```text
begin -> complete -> approve -> exchange -> refresh -> refresh
begin -> complete -> deny -> exchange
approve twice
exchange with wrong verifier, then correct verifier
refresh old generation after rotation
refresh during transient dependency error, then retry
```

The public API remains ordinary; generated sequence tests are internal verification.

### 19.3 Store conformance

Every store implementation must pass the same suite:

- one-time consumption;
- wrong binding does not consume;
- exactly one winner under concurrency;
- atomic code-to-refresh transition;
- atomic refresh rotation;
- family revocation on replay;
- expiry classification;
- capacity admission;
- child-to-parent pruning;
- no plaintext credential persistence.

### 19.4 HTTP conformance

Test metadata and all endpoint flows with structured decoding. Cover malformed bodies, trailing JSON, oversized fields, unsupported methods/content types/grants, wrong resources, redirect safety, consent-token CSRF/replay, framing headers, and error redirects only after a trusted redirect has been established.

Add the focused OWASP WSTG cases needed for shipping: redirect URI mutation, code binding/replay rejection, PKCE omission/downgrade/wrong verifier, consent form token and framing, access-token expiry/wrong audience, refresh expiry/rotation/replay, and transient-revalidation retry.

### 19.5 Token tests

- issuer, audience, expiry, not-before, issued-at, fixed algorithm/type, key ID, subject, client ID, and scope;
- key overlap and removal timing;
- reserved claim collision and token-supplied key-material rejection;
- stable JWKS;
- token for Resource A rejected for Resource B;
- missing token/scope and unclassified protected operations fail closed.

### 19.6 Security tooling

```bash
GOWORK=off go test ./... -count=1
GOWORK=off go test -race ./... -count=1
GOWORK=off go vet ./...
make fmt-check
make lint
make gosec
make govulncheck
```

Add fuzzing for pure parsers and run dependency/secret scanning in CI.

### 19.7 Consolidated final smoke

There is one deployed smoke target, `make smoke-final`, and it runs only at the end of Phase 12. Its scope is the compact happy-path and one cross-audience rejection listed in Phase 12.

Everything broader stays out of smoke:

- fake GEC and full OAuth lifecycle run as local integration tests;
- code/refresh replay, revocation, capability changes, expiry, malformed JWTs, and OWASP cases run deterministically before deployment;
- key rotation, outage, storage pressure, and rate/capacity behavior run as explicit operational exercises;
- Claude and ChatGPT each perform one link/list/call check before a release that changes host-facing OAuth behavior, not on every development turn;
- the routine final smoke may use one representative MCP host/official SDK client, while both real hosts are a release/manual interoperability gate only when relevant.

The smoke should finish in minutes excluding unavoidable human login/consent time, fail fast, and never mutate shared employee policy or reusable client grants.

## 20. Extraction mapping

| Current source | Target | Notes |
|---|---|---|
| `mcpoauth/provider.go:85-147` | `oauthserver/config.go` | Remove GEC/MCP coupling |
| `provider.go:149-239` | `httptransport/metadata.go`, `jwttokens/jwks.go` | Typed metadata instead of maps internally |
| `provider.go:255-313` | engine registration + HTTP DCR | Add lifecycle policy |
| `provider.go:315-360` | `Engine.BeginAuthorization` | Resource registry and login context |
| `provider.go:363-392` | CoinVault callback adapter + `Engine.CompleteLogin` | GEC exchange stays in CoinVault |
| `provider.go:395-449` | consent engine + secure default template | Add client snapshot |
| `provider.go:451-550` | code/refresh transitions | Fix mutation ordering and revalidation outcomes |
| `provider.go:553-572` | `jwttokens` | Generic claims plus application enrichment |
| `provider.go:575-585` | engine revocation + HTTP handler | Preserve non-disclosure |
| `provider.go:592-761` | value/parser/error packages | Pure tests and fuzzing |
| `store.go:30-80` | generic domain records | Principal becomes typed generic |
| `store.go:82-171` | `sqlitestore` open/schema/migrations | Explicit schema versions |
| `store.go:174-435` | client/transaction/consent/code transitions | Commit APIs, bounds, pruning |
| `store.go:437-550` | refresh transitions | Preserve replay-family semantics |
| `mcpauthz/gec_client.go` | CoinVault identity adapter | Does not move into generic library |
| `mcpauthz/capabilities.go` | CoinVault scope policy | Does not move into generic library |
| `go-go-mcp/auth_provider.go` | MCP adapter consumes `VerifiedAccessToken` | oh-auth must not import go-go-mcp |

## 21. Code review guide

Review implementation in dependency order, not HTTP route order:

1. Value types and scope invariants.
2. Transition input/result definitions.
3. Store commit atomicity.
4. Token reserved claims and audience.
5. Engine mutation ordering.
6. HTTP parsing and safe error mapping.
7. Consent mandatory fields.
8. CoinVault identity/policy adapters.
9. MCP and RAG resource adapters.

Questions reviewers should answer:

- Can any adapter produce a final grant without engine intersection?
- Can any failure consume a retryable credential before all output is prepared?
- Can a wrong client, redirect, verifier, or resource consume a code?
- Can refresh expand scopes?
- Can a transient identity failure revoke a family?
- Can an untrusted client appear verified?
- Can any table grow beyond policy?
- Can a token cross resource boundaries?
- Can a credential or service secret reach logs or persistent plaintext?

## 22. Risks and alternatives

### Risk: generic types spread through too many packages

One principal attribute parameter is intentional. Avoid adding separate generic parameters for claims, clients, and resources. If an adapter needs dynamic JWT claims, keep that dynamism at the JSON boundary.

### Risk: interface surface becomes large

The store has many methods because transitions are distinct. A small CRUD interface would be cosmetically shorter but less safe. Group methods by transition in files and provide conformance tests.

### Risk: extraction changes behavior while moving code

Port existing tests first, then make the three designed hardenings explicit. Keep extraction commits small and compare wire fixtures. Do not run old and new production providers simultaneously.

### Risk: multi-resource support adds complexity

The complexity is limited to an immutable registry and one resource parameter in policy. It avoids creating separate, drifting authorization servers for MCP and RAG.

### Alternative: adopt a large existing OAuth server framework

A mature framework may cover more RFCs, but CoinVault already has narrow behavior, GEC federation, custom consent, resource binding, and lifecycle requirements. Evaluate dependencies during Phase 0, but do not wrap a large framework while also preserving a parallel custom state machine. Choose one source of truth.

### Alternative: put OAuth in go-go-mcp

Rejected. A RAG HTTP server should not import MCP protocol code, and OAuth authorization-server concerns should not enlarge MCP core.

### Alternative: use `map[string]any` principal everywhere

Rejected for policy code. It defers identity mistakes to runtime and makes schema evolution unclear. Restrict dynamic maps to external JWT claims.

### Alternative: event sourcing

A complete event log could model transitions elegantly but is unnecessary for current scale and complicates credential deletion. Atomic current-state tables plus redacted audit events are sufficient.

## 23. Open questions

These questions need concrete consumer evidence before implementation choices are finalized:

1. Will one deployed issuer serve both MCP and RAG resources, or will each application embed its own instance?
2. Must existing development refresh grants survive CoinVault cutover?
3. Which pure-Go SQLite driver version should be pinned after concurrency and migration tests?
4. Does the first RAG server need organization claims in access tokens, or can it resolve policy by subject?
5. Should oh-auth expose a small standalone server binary, or remain library-only with examples?

None blocks domain and transition implementation. Existing grant migration is the only question that may require explicit user approval because repository guidance rejects compatibility work by default.

## 24. Intern implementation checklist

- [ ] I can explain principal, client, authorization server, resource server, resource, scope, PKCE, code, refresh family, and consent.
- [ ] The repository has the correct module and no `XXX` placeholders.
- [ ] Core package does not import HTTP, SQLite, JWT libraries, CoinVault, or MCP.
- [ ] Principal attributes are typed.
- [ ] Scope sets are canonical and immutable to callers.
- [ ] Every grant carries exactly one resource.
- [ ] Final scopes are always computed by the engine.
- [ ] Store methods commit full transitions atomically.
- [ ] Wrong bindings do not consume credentials.
- [ ] Code exchange prepares output before commit.
- [ ] Refresh transient failures preserve the current grant.
- [ ] Refresh ineligibility and replay revoke the family.
- [ ] DCR clients are unverified and bounded.
- [ ] Consent displays exact destination, resource, scopes, and authorization lifetime.
- [ ] The one-time consent form token rejects missing, wrong, expired, and replayed submissions.
- [ ] Consent responses are no-store, unframeable, no-referrer, and nosniff.
- [ ] SQLite pruning preserves active replay history.
- [ ] JWT reserved claims cannot be overwritten and token headers cannot select trust material.
- [ ] MCP and RAG reject each other's tokens by audience and deny unclassified operations by default.
- [ ] HTTP methods, content types, sizes, and timeouts are explicit.
- [ ] Focused OWASP/WSTG negative tests pass locally; they are not deployed smoke steps.
- [ ] Store, token, engine, and HTTP conformance suites pass.
- [ ] No implementation phase requires a deployed smoke run.
- [ ] The one consolidated `make smoke-final` target passes after release-candidate deployment.
- [ ] CoinVault passes with `GOWORK=off` against a published oh-auth version.
- [ ] Duplicate CoinVault OAuth mechanics are removed after cutover.

## 25. API and file reference map

### oh-auth current repository

- `go.mod:1-7` — template module and current toolchain/dependency baseline.
- `Makefile:19-52` — quality gates and placeholder logcopter configuration.
- `README.md` — template content to replace.
- `pkg/doc.go`, `pkg/logcopter.go`, `cmd/XXX/main.go` — placeholder package/binary.
- `.github/workflows/` — existing release and security workflows to normalize.

### CoinVault source implementation

- `coinvault/internal/mcpoauth/provider.go:37-83` — current coupled interfaces, configuration, and claims.
- `provider.go:85-220` — validation, routes, token verification, and metadata.
- `provider.go:255-449` — registration, authorization, login completion, and consent.
- `provider.go:451-585` — code exchange, refresh, signing, and revocation.
- `provider.go:592-761` — URL, PKCE, secret, scope, and HTTP helpers.
- `coinvault/internal/mcpoauth/store.go:18-80` — errors and domain records.
- `store.go:82-171` — SQLite construction and schema.
- `store.go:174-435` — client through authorization-code state.
- `store.go:437-550` — refresh lookup, rotation, replay, and revocation.
- `coinvault/internal/mcpoauth/provider_test.go` — end-to-end protocol fixture.
- `coinvault/internal/mcpoauth/store_test.go` — persistence lifecycle and concurrency baseline.
- `coinvault/internal/mcpoauth/key.go` — key parsing helpers.

### CoinVault application adapters

- `coinvault/internal/mcpauthz/gec_client.go:26-147` — GEC principal and back-channel behavior.
- `coinvault/internal/mcpauthz/capabilities.go:8-77` — application capabilities and scope projection.
- `coinvault/cmd/coinvault/cmds/mcp.go:127-173` — current composition root.

### MCP integration

- `go-go-mcp/pkg/embeddable/auth_provider.go:15-34` — current principal/provider boundary.
- `go-go-mcp/pkg/embeddable/official_backend.go:292-394` — route mounting, bearer enforcement, metadata, and context injection.
- MCP authorization specification 2025-11-25 — resource-server discovery and OAuth requirements.

### Design inputs

- `COINVAULT-OAUTH-CONSENT-IDENTITY` — client trust and destination snapshot.
- `COINVAULT-OAUTH-REFRESH-REVALIDATION` — explicit authoritative versus transient outcomes.
- `COINVAULT-OAUTH-STATE-LIFECYCLE` — bounded registration and persistence.
- `2026-08-28-GEC-COINVAULT-MCP-AUTHZ` — GEC capability federation and refresh intent.

### Standards

- RFC 6749 — OAuth 2.0 framework.
- RFC 7591 — Dynamic Client Registration.
- RFC 7636 — PKCE.
- RFC 7009 — Token Revocation.
- RFC 8414 — Authorization Server Metadata.
- RFC 8707 — Resource Indicators.
- RFC 9728 — Protected Resource Metadata.
- [OWASP OAuth2 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html), especially PKCE, replay prevention, and access-token privilege restriction.
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), especially JWT, methods, workflow state, input validation, and security headers.
- [OWASP WSTG OAuth Authorization Server Weaknesses](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses).
- Local OWASP source manifest: `sources/owasp/README.md`.
- Deferred controls and full ASVS crosswalk: `design-doc/02-deferred-owasp-hardening-and-higher-assurance-roadmap.md`.

## 26. Definition of done

The extraction is complete when:

1. oh-auth has a normalized module and documented public packages;
2. engine, SQLite, JWT, and HTTP conformance tests pass;
3. all three review hardenings are implemented in oh-auth;
4. CoinVault uses oh-auth and no longer contains generic OAuth state/token logic;
5. go-go-mcp consumes only a small verifier/metadata adapter;
6. one independent RAG server validates tokens for a distinct resource;
7. cross-resource tokens are rejected;
8. CoinVault passes full validation with `GOWORK=off` against a published version;
9. old duplicate code is deleted rather than retained as compatibility fallback;
10. operational docs cover key rotation, state backup, pruning, quotas, and incident revocation;
11. consent responses apply the minimal browser headers and one-time form-token checks;
12. JWT verification uses fixed trust configuration and rejects attacker-selected key material;
13. MCP and RAG enforcement is deny-by-default on every protected operation;
14. the focused OWASP/WSTG shipping test set passes deterministically before deployment;
15. one consolidated, non-destructive final smoke passes after release-candidate deployment.

## 27. Minimal OWASP shipping delta

The complete downloaded OWASP corpus remains under `sources/owasp/`, but v0.1 does not claim ASVS certification. The following additions are the entire required delta over the original extraction design:

| Addition | Implementation impact |
|---|---|
| Consent headers | Set CSP anti-framing/form restrictions, X-Frame-Options, no-referrer, no-store, and nosniff. |
| Consent form token | Treat the existing random, expiring, one-time consent token as the synchronizer token and test failure/replay. No new cookie/session subsystem. |
| Consent lifetime | Show access-token lifetime and absolute offline authorization expiry. |
| JWT trust | Fix algorithm/type/key ring; reject `none`, wrong type, and token-supplied key material. Mostly verifier tests. |
| HTTP strictness | Enforce methods, content types, sizes, and server/upstream timeouts. |
| Consumer enforcement | Deny protected MCP/RAG operations by default; validate audience and scopes every request. |
| Focused tests | Automate the relevant WSTG redirect, code, PKCE, consent, lifetime, audience, and refresh cases locally; do not turn the matrix into deployed smoke steps. |
| Final smoke | Run one non-destructive end-to-end orchestrator only after release-candidate deployment. |

Everything else discovered during the OWASP review is intentionally outside the v0.1 critical path and documented in [Deferred OWASP Hardening and Higher Assurance Roadmap](02-deferred-owasp-hardening-and-higher-assurance-roadmap.md). The source manifest provides direct links to the broader guidance without converting every recommendation into initial implementation scope.
