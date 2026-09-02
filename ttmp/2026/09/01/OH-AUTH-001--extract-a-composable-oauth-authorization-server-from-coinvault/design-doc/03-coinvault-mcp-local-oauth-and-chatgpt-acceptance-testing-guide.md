---
Title: CoinVault MCP Local OAuth and ChatGPT Acceptance Testing Guide
Ticket: OH-AUTH-001
Status: active
Topics:
    - architecture
    - golang
    - oauth
    - security
DocType: design-doc
Intent: long-term
Owners: []
RelatedFiles:
    - Path: repo://pkg/httptransport/server.go
      Note: Authorization-server discovery and HTTP routes
    - Path: ws://coinvault/cmd/coinvault/cmds/mcp.go
      Note: CoinVault MCP and OAuth composition command
    - Path: ws://coinvault/internal/mcpconn/server.go
      Note: Canonical MCP route and verifier integration
    - Path: ws://coinvault/internal/mcpoauth/provider.go
      Note: GEC-backed OH Auth provider
    - Path: ws://coinvault/internal/ragresource/server.go
      Note: Independent RAG audience boundary
    - Path: ws://go-go-mcp/pkg/embeddable/official_backend.go
      Note: Official SDK transport and protected-resource metadata
ExternalSources: []
Summary: Reproducible staged guide for testing CoinVault's real Streamable HTTP MCP endpoint locally, through OAuth, and from ChatGPT.
LastUpdated: 2026-09-02T15:30:00Z
WhatFor: ""
WhenToUse: ""
---


# CoinVault MCP Local, OAuth, and ChatGPT Acceptance Testing Guide

## Executive summary

This guide defines the next-session acceptance procedure for CoinVault's MCP integration. It begins with an unauthenticated loopback server, advances to a real local MCP client, then introduces CoinVault's OH Auth authorization server and GEC identity adapter behind a public HTTPS endpoint. ChatGPT is tested only after the transport, discovery, and OAuth layers pass independently.

The procedure deliberately separates failures by layer. A failed MCP initialize request is not debugged as an OAuth problem. A failed browser callback is not debugged as a tool-registration problem. Each phase has entry criteria, commands, expected observations, evidence to retain, and stop conditions.

No phase bypasses production publication controls. A temporary tunnel may be used for interoperability testing, but it must expose a dedicated test configuration and must not be represented as the deployed production smoke. The final deployed smoke remains a separate release acceptance action.

## 1. Goal and acceptance boundary

The goal is to prove that a real MCP client can discover CoinVault, complete authorization, establish a Streamable HTTP MCP session, list tools, invoke an authorized read-only tool, and remain isolated from other sessions and OAuth resources.

The complete acceptance boundary includes:

1. CoinVault process startup with released dependencies.
2. Streamable HTTP MCP at the exact `/mcp` path.
3. MCP initialize, tool listing, and tool invocation.
4. RFC 9728 protected-resource metadata.
5. RFC 8414 authorization-server metadata.
6. Dynamic client registration for a public client.
7. Authorization Code plus PKCE S256.
8. GEC-backed employee authentication and capability mapping.
9. Consent disclosure and scope reduction.
10. Exact MCP audience validation.
11. Refresh behavior and revocation behavior.
12. Per-session evidence-ledger isolation.
13. Negative MCP-versus-RAG audience tests.
14. ChatGPT connector interoperability.

## 2. Non-goals

This guide does not:

- deploy to production;
- bypass ECR or protected GitHub environment controls;
- test write-capable SQL authority;
- use a production signing key in a local tunnel;
- expose a local database or service token in logs;
- claim that a temporary tunnel is the final deployed smoke;
- retest every OH Auth store conformance invariant already covered by deterministic tests.

## 3. Current architecture under test

CoinVault is the composition root. In `cmd/coinvault/cmds/mcp.go`, it opens the OH Auth SQLite store, loads the RSA signing key, constructs `mcpoauth.Provider`, assigns that provider as the MCP `HTTPAuthVerifier`, and explicitly assigns `Provider.MountAuthorizationServer` as the authorization-route mounter.

`internal/mcpconn/server.go` creates the public `http.ServeMux`, mounts the authorization server when configured, and passes the verifier to go-go-mcp. go-go-mcp owns MCP transport behavior, bearer enforcement, protected-resource metadata mounting, and principal propagation. It does not own CoinVault's authorization server.

OH Auth's `httptransport.Server.Mount` publishes:

- `/.well-known/oauth-authorization-server`;
- `/jwks.json`;
- `/oauth/register`;
- `/oauth/authorize`;
- `/oauth/consent`;
- `/oauth/token`;
- `/oauth/revoke`.

CoinVault's GEC callback is mounted at `/oauth/gec/callback`. It exchanges the identity assertion through the configured GEC service, converts the employee identity and capabilities into a generic OH Auth principal, and permits policy to reduce scopes.

The MCP protected resource is an exact URL ending in `/mcp`. The RAG protected resource is distinct and accepts only tokens with its exact audience.

## 4. Release baseline

Run all tests from a clean CoinVault checkout with workspace substitution disabled where dependency independence matters.

Expected direct versions:

```text
github.com/go-go-golems/oh-auth v0.0.5
github.com/go-go-golems/go-go-mcp v0.1.0
```

Verify:

```bash
cd /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault

git status --short --branch
GOWORK=off go list -m github.com/go-go-golems/oh-auth
GOWORK=off go list -m github.com/go-go-golems/go-go-mcp
```

The expected result is a clean tree and the two release tags above. Do not proceed from a pseudo-version.

## 5. Test topology

### 5.1 Loopback topology

```text
local MCP client
    |
    | Streamable HTTP
    v
http://127.0.0.1:8081/mcp
    |
    +-- CoinVault tool registry
    +-- optional local database
    +-- optional verified knowledge bundle
```

This topology uses `auth-mode=none`. It proves MCP behavior only.

### 5.2 Public OAuth topology

```text
ChatGPT or local OAuth-capable MCP client
    |
    | HTTPS
    v
public test origin
    +-- /mcp
    +-- /.well-known/oauth-protected-resource
    +-- /.well-known/oauth-authorization-server
    +-- /jwks.json
    +-- /oauth/register
    +-- /oauth/authorize
    +-- /oauth/consent
    +-- /oauth/token
    +-- /oauth/revoke
    +-- /oauth/gec/callback
              |
              | authenticated back channel
              v
          GEC identity service
```

Use one stable public origin for the first MCP OAuth test. The configured issuer must exactly match that origin, and the configured MCP resource must exactly equal that origin plus `/mcp`.

## 6. Evidence directory

Create a private, ignored evidence directory before testing:

```bash
export ACCEPTANCE_DIR="$(mktemp -d /tmp/coinvault-mcp-acceptance.XXXXXX)"
printf '%s\n' "$ACCEPTANCE_DIR"
```

Store only sanitized material:

- command versions;
- public metadata responses;
- HTTP status and response headers with credentials removed;
- MCP tool names and sanitized results;
- timestamps and client names;
- pass/fail notes.

Never retain:

- access tokens;
- refresh tokens;
- authorization codes;
- GEC service tokens;
- private signing keys;
- session cookies;
- database passwords.

## 7. Phase 0: deterministic preflight

### Purpose

Establish that the candidate is locally healthy before introducing processes, browsers, clients, or tunnels.

### Commands

```bash
cd /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault

GOWORK=off go test ./internal/mcpconn ./internal/mcpoauth \
  ./internal/ragresource ./internal/ragapi ./internal/knowledge \
  ./cmd/coinvault/cmds -count=1

GOWORK=off go test -race ./internal/mcpconn ./internal/mcpoauth \
  ./internal/ragresource ./internal/ragapi ./internal/knowledge -count=1

GOWORK=off go vet ./internal/mcpconn ./internal/mcpoauth \
  ./internal/ragresource ./internal/ragapi ./internal/knowledge \
  ./cmd/coinvault/cmds
```

If this session follows a dependency or release change, run the repository's complete pre-push target as well.

### Pass criteria

- Every command exits zero.
- No uncommitted generated asset changes remain.
- CoinVault resolves OH Auth and go-go-mcp to release tags.

### Stop conditions

Stop before runtime testing if any deterministic test, race test, or vet fails.

## 8. Phase 1: loopback MCP transport

### Purpose

Prove the real official-SDK Streamable HTTP path without OAuth.

### Start the server

Use a dedicated terminal:

```bash
cd /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault

GOWORK=off go run ./cmd/coinvault mcp serve \
  --listen 127.0.0.1:8081 \
  --resource-url http://127.0.0.1:8081/mcp \
  --issuer-url http://127.0.0.1:8081 \
  --auth-mode none
```

If the command requires the RAG resource in the current build, add a distinct loopback value:

```text
--rag-resource-url http://127.0.0.1:8082/api
```

### Probe HTTP readiness

```bash
curl -fsS http://127.0.0.1:8081/healthz | tee "$ACCEPTANCE_DIR/phase1-health.json"
```

Expected status:

```json
{"status":"ok"}
```

### Run the bundled MCP smoke

In a second terminal:

```bash
cd /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault

GOWORK=off go run ./cmd/coinvault-mcp-smoke \
  --endpoint http://127.0.0.1:8081/mcp
```

### Pass criteria

- Health probe succeeds.
- MCP initialize succeeds.
- The client receives a server identity.
- Tool discovery returns at least `connector_status` when no domain registry is configured.
- Calling the status tool succeeds.
- Server logs contain no panic, token, or credential material.

### Failure triage

| Symptom | First boundary to inspect |
|---|---|
| Connection refused | listener and process startup |
| HTTP 404 | exact `/mcp` route |
| MCP initialize error | official SDK protocol negotiation |
| Empty tool list | tool registry construction |
| Process exits after request | server lifecycle and request logs |

Do not enable OAuth until this phase passes.

## 9. Phase 2: production-shaped local tools

### Purpose

Prove that the MCP transport invokes CoinVault's actual read-only tool registry rather than only the status fixture.

### Configure data inputs

Choose the minimum read-only configuration needed for one useful tool:

- a verified immutable knowledge bundle for knowledge search; or
- a read-only database account and SQL documentation for safe SQL tools.

Prefer the knowledge bundle for the first test because it avoids network database authority.

Example shape:

```bash
GOWORK=off go run ./cmd/coinvault mcp serve \
  --listen 127.0.0.1:8081 \
  --resource-url http://127.0.0.1:8081/mcp \
  --issuer-url http://127.0.0.1:8081 \
  --auth-mode none \
  --knowledge-bundle /absolute/path/to/verified-bundle \
  --knowledge-scratch-dir "$ACCEPTANCE_DIR/scratch"
```

Add the required embedding profile flags if the selected bundle contains vector indexes.

### Assertions

1. Tool discovery includes the intended knowledge tool.
2. A bounded read query succeeds.
3. The output includes stable evidence labels.
4. Repeating a query within one session reuses the same ledger.
5. A new MCP session begins with its own evidence budget and starts labels at `E1`.
6. A client-controlled request cannot inject document authorization fields.

### Pass criteria

A real domain tool succeeds and two sessions do not share evidence budgets or labels.

## 10. Phase 3: local agent clients

### Purpose

Test an agent-facing MCP client before involving ChatGPT's hosted connector and browser OAuth flow.

### Client choice

Use a client that supports Streamable HTTP URLs. Before adding configuration, inspect the installed version's help because MCP configuration syntax changes over time:

```bash
claude mcp --help
codex mcp --help
pi --help
```

Do not assume a client supports OAuth merely because it supports local stdio MCP.

### Generic remote configuration

The conceptual configuration is:

```json
{
  "mcpServers": {
    "coinvault-local": {
      "url": "http://127.0.0.1:8081/mcp"
    }
  }
}
```

For clients with a command-based registration interface, use the command shown by that installed client's help and supply:

```text
name: coinvault-local
transport: http or streamable-http
url: http://127.0.0.1:8081/mcp
```

### Agent prompts

Use deterministic prompts that force observable MCP behavior:

```text
List the tools exposed by the coinvault-local MCP server. Do not call any tool.
```

```text
Call the CoinVault connector status tool and return its structured result unchanged.
```

For a configured knowledge bundle:

```text
Use only the CoinVault MCP knowledge tool to answer: <fixed fixture question>.
Include every evidence identifier returned by the tool.
```

### Evidence

Record:

- client name and version;
- exact registration command with secrets removed;
- discovered tool names;
- called tool name;
- sanitized result;
- CoinVault server timestamp corresponding to the request.

### Pass criteria

At least one local agent client initializes, lists tools, and calls a real tool over Streamable HTTP.

## 11. Phase 4: OAuth test configuration

### Purpose

Prepare isolated OAuth state and key material before exposing the server publicly.

### Generate a test signing key

```bash
install -d -m 0700 "$ACCEPTANCE_DIR/secrets" "$ACCEPTANCE_DIR/state"
openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out "$ACCEPTANCE_DIR/secrets/oauth-signing-key.pem"
chmod 0600 "$ACCEPTANCE_DIR/secrets/oauth-signing-key.pem"
```

Do not reuse production keys.

### Prepare the GEC service credential

Write the test-environment GEC service token to a mode-0600 file without printing it:

```bash
install -m 0600 /secure/source/gec-test-service-token \
  "$ACCEPTANCE_DIR/secrets/gec-service-token"
```

### Choose canonical URLs

Set one stable public HTTPS origin:

```bash
export MCP_ORIGIN=https://mcp-test.example.com
export MCP_RESOURCE="$MCP_ORIGIN/mcp"
export RAG_RESOURCE=https://rag-test.example.com/api
```

Invariants:

- issuer equals `MCP_ORIGIN` exactly;
- MCP resource equals `MCP_ORIGIN/mcp` exactly;
- RAG resource differs from MCP resource;
- no query or fragment appears in either resource;
- public URLs use HTTPS;
- the tunnel or proxy preserves the external host and scheme.

## 12. Phase 5: public HTTPS exposure

### Decision: Use a controlled test origin before ChatGPT

- **Context:** ChatGPT cannot reach loopback addresses and OAuth redirect targets must be public HTTPS URLs.
- **Options considered:** production deployment, temporary HTTPS tunnel, local-only test.
- **Decision:** Use an approved test deployment when available; otherwise use a controlled temporary tunnel with dedicated test keys and state.
- **Rationale:** This permits external interoperability debugging without claiming production acceptance or bypassing artifact publication controls.
- **Consequences:** DNS, forwarding headers, tunnel lifetime, and callback stability become part of the test. The tunnel must be removed afterward.
- **Status:** accepted

Start CoinVault bound only to loopback behind the tunnel or reverse proxy:

```bash
GOWORK=off go run ./cmd/coinvault mcp serve \
  --listen 127.0.0.1:8081 \
  --auth-mode gec_oauth \
  --resource-url "$MCP_RESOURCE" \
  --issuer-url "$MCP_ORIGIN" \
  --rag-resource-url "$RAG_RESOURCE" \
  --gec-base-url https://GEC-TEST-ORIGIN \
  --gec-service-token-file "$ACCEPTANCE_DIR/secrets/gec-service-token" \
  --oauth-db "$ACCEPTANCE_DIR/state/oauth.db" \
  --oauth-signing-key "$ACCEPTANCE_DIR/secrets/oauth-signing-key.pem" \
  --oauth-key-id coinvault-acceptance-1
```

Configure the tunnel to forward the public test origin to `http://127.0.0.1:8081`. Do not expose unrelated local ports.

### TLS and routing preflight

```bash
curl --fail --show-error --silent \
  "$MCP_ORIGIN/healthz" | jq .

curl --fail --show-error --silent \
  "$MCP_ORIGIN/.well-known/oauth-protected-resource" \
  | tee "$ACCEPTANCE_DIR/protected-resource.json" | jq .

curl --fail --show-error --silent \
  "$MCP_ORIGIN/.well-known/oauth-authorization-server" \
  | tee "$ACCEPTANCE_DIR/authorization-server.json" | jq .

curl --fail --show-error --silent \
  "$MCP_ORIGIN/jwks.json" \
  | tee "$ACCEPTANCE_DIR/jwks.json" | jq .
```

### Metadata assertions

Protected-resource metadata must contain:

```json
{
  "resource": "https://mcp-test.example.com/mcp",
  "authorization_servers": ["https://mcp-test.example.com"]
}
```

Authorization-server metadata must contain endpoint URLs on the exact issuer origin and advertise:

- response type `code`;
- grants `authorization_code` and `refresh_token`;
- PKCE method `S256`;
- token endpoint authentication method `none`;
- the expected MCP and RAG scopes.

JWKS must contain the configured key ID and an RSA signing key. It must not contain private key fields.

### Unauthenticated challenge

Send a syntactically complete initialize request without a bearer token:

```bash
curl --include --request POST "$MCP_RESOURCE" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json, text/event-stream' \
  --data '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2025-06-18",
      "capabilities":{},
      "clientInfo":{"name":"curl-preflight","version":"1"}
    }
  }'
```

Expected result:

- HTTP `401`;
- `WWW-Authenticate: Bearer ...`;
- a `resource_metadata` parameter naming the public protected-resource metadata URL;
- no MCP initialize result.

## 13. Phase 6: manual OAuth protocol walk

### Purpose

Verify discovery, registration, browser identity, consent, code exchange, and bearer use independently of ChatGPT.

### Register a test public client

Use a callback controlled by the selected local OAuth test client. Example request shape:

```bash
curl --fail --show-error --silent \
  --request POST "$MCP_ORIGIN/oauth/register" \
  --header 'Content-Type: application/json' \
  --data '{
    "client_name":"CoinVault acceptance client",
    "redirect_uris":["https://CLIENT-CALLBACK.example/callback"],
    "token_endpoint_auth_method":"none",
    "grant_types":["authorization_code","refresh_token"],
    "response_types":["code"],
    "scope":"coinvault:knowledge:read offline_access"
  }' | jq .
```

Do not put the returned client ID or later credentials into the tracked repository.

### Browser authorization assertions

The client must generate a fresh PKCE verifier and S256 challenge. The authorization request must include:

- registered client ID;
- exact registered redirect URI;
- response type `code`;
- nonempty state;
- PKCE S256 challenge;
- explicit MCP resource;
- requested scopes.

During the flow verify:

1. The browser redirects to the configured GEC test origin.
2. GEC authenticates the intended test employee.
3. The callback returns to `/oauth/gec/callback` with the transaction binding.
4. The consent page displays the registered client name.
5. The consent page displays the exact callback destination.
6. The consent page displays the MCP resource and requested scopes.
7. Approval redirects only to the registered URI.
8. State is unchanged.

### Token exchange assertions

Exchange the code with the original PKCE verifier. Verify without retaining token strings:

- token type is Bearer;
- access token is nonempty;
- expiration is bounded;
- granted scope is no broader than requested and policy-allowed scope;
- refresh token is present only when `offline_access` was granted.

Use the access token once against `/mcp`, then remove it from shell history and temporary files.

## 14. Phase 7: ChatGPT connector

### Entry criteria

Do not begin until all of the following pass:

- local MCP smoke;
- one local agent client;
- public TLS health;
- protected-resource metadata;
- authorization-server metadata;
- JWKS;
- unauthenticated challenge;
- one manual or test-client OAuth flow.

### Registration

In ChatGPT's connector or developer settings, create a custom remote MCP connector and supply:

```text
https://mcp-test.example.com/mcp
```

The UI location and terminology can change. Record the observed ChatGPT UI label and date rather than treating a screenshot as a stable API contract.

Do not manually paste a bearer token if automatic OAuth discovery is the behavior under test.

### Expected sequence

1. ChatGPT requests protected-resource metadata.
2. ChatGPT requests authorization-server metadata.
3. ChatGPT dynamically registers a public client.
4. ChatGPT opens the browser authorization endpoint with PKCE and the MCP resource.
5. CoinVault redirects to GEC.
6. The employee authenticates.
7. CoinVault displays consent with ChatGPT's registered identity and exact callback.
8. The employee approves read-only scopes.
9. ChatGPT exchanges the authorization code.
10. ChatGPT initializes an authenticated MCP session.
11. ChatGPT discovers tools.

### Chat prompts

Start with discovery:

```text
List the tools available from the CoinVault connector. Do not call a tool yet.
```

Then call a harmless tool:

```text
Call the CoinVault connector status tool and show the returned structured data.
```

Then call one read-only domain tool:

```text
Use the CoinVault knowledge connector to answer: <fixed acceptance question>.
Report the evidence identifiers returned by CoinVault.
```

### Pass criteria

- OAuth is discovered automatically.
- The browser flow returns to ChatGPT.
- Consent identifies the destination client and callback.
- ChatGPT lists CoinVault tools.
- A read-only tool call succeeds.
- CoinVault logs attribute the request to a verified principal and client without logging credentials.

## 15. Phase 8: security and isolation acceptance

### 15.1 Exact audience isolation

Obtain independent MCP and RAG grants from the same issuer.

Assert:

1. MCP token succeeds at `/mcp`.
2. MCP token fails at `POST /api/rag/query`.
3. RAG token succeeds at the RAG endpoint with required scope.
4. RAG token fails at `/mcp`.
5. Refreshing a RAG grant yields another RAG-bound access token, never an MCP token.

### 15.2 Scope enforcement

Assert:

- missing token returns `401`;
- malformed token returns `401`;
- valid token lacking a route's required scope returns `403`;
- policy cannot expand requested scopes;
- an empty route policy is rejected during construction;
- request JSON cannot inject authorization capabilities.

### 15.3 Session isolation

Open two independent MCP client sessions and run the same knowledge call.

Assert:

- each session begins evidence labels at `E1`;
- exhausting one session's evidence budget does not affect the other;
- closing one session does not invalidate the other's bearer credential;
- principal and client identity remain scoped to each request context.

### 15.4 Refresh and revalidation

Assert:

- successful refresh rotates the refresh credential;
- replay of an old generation revokes or rejects according to the family policy;
- authoritative employee ineligibility revokes the family;
- transient GEC transport/internal failure returns a temporary failure without revoking the family;
- recovery permits a later refresh.

### 15.5 Revocation and expiry

Assert:

- revocation invalidates the targeted refresh family;
- expired authorization codes cannot be exchanged;
- consumed codes cannot be replayed;
- expired access tokens fail resource verification.

## 16. Phase 9: cleanup

Remove the connector from ChatGPT and local clients. Stop CoinVault and the tunnel. Delete the temporary state and secrets:

```bash
rm -rf -- "$ACCEPTANCE_DIR"
unset ACCEPTANCE_DIR MCP_ORIGIN MCP_RESOURCE RAG_RESOURCE
```

Confirm:

- tunnel hostname no longer routes to the workstation;
- no test token remains in shell history or logs;
- no private key or service token entered Git;
- no temporary callback remains registered beyond its retention period;
- repository trees are clean.

## 17. Final deployed smoke

The temporary acceptance flow does not replace the final deployed smoke. After approved artifact publication and deployment, repeat only the narrow final checks against the release environment:

1. Fetch MCP protected-resource metadata.
2. Fetch authorization-server metadata and JWKS.
3. Complete one real MCP authorization.
4. Initialize one authenticated MCP session.
5. Call one read-only tool.
6. Confirm MCP token rejection at RAG.
7. Confirm RAG token rejection at MCP.
8. Record deployed image/version evidence.

Do not add broad exploratory checks to this final smoke. Exploratory debugging belongs in the earlier phases.

## 18. Acceptance checklist

### Local

- [ ] Candidate uses OH Auth `v0.0.5`.
- [ ] Candidate uses go-go-mcp `v0.1.0`.
- [ ] Deterministic normal/race/vet gates pass.
- [ ] Loopback health succeeds.
- [ ] Bundled MCP smoke initializes and calls a tool.
- [ ] A real CoinVault domain tool succeeds.
- [ ] Two local sessions have independent evidence ledgers.
- [ ] One local agent client lists and invokes tools.

### Public OAuth

- [ ] Public HTTPS health succeeds.
- [ ] Protected-resource metadata is exact.
- [ ] Authorization-server metadata is exact.
- [ ] JWKS contains only public key material.
- [ ] Unauthenticated `/mcp` returns a discovery challenge.
- [ ] Dynamic registration succeeds within configured bounds.
- [ ] PKCE S256 authorization succeeds.
- [ ] GEC identity exchange succeeds.
- [ ] Consent displays client and exact destination.
- [ ] Token exchange and authenticated MCP initialize succeed.

### ChatGPT

- [ ] ChatGPT discovers OAuth without a pasted token.
- [ ] Browser authorization returns to ChatGPT.
- [ ] Tool discovery succeeds.
- [ ] Status tool succeeds.
- [ ] One read-only domain tool succeeds.

### Negative and lifecycle

- [ ] MCP and RAG audiences reject each other's tokens.
- [ ] Missing scope is denied.
- [ ] Request-controlled authority injection is denied.
- [ ] Transient GEC failure preserves the refresh family.
- [ ] Authoritative ineligibility revokes the refresh family.
- [ ] Refresh replay is rejected.
- [ ] Revocation and expiry are enforced.

### Cleanup and release

- [ ] Temporary connector and tunnel are removed.
- [ ] Temporary credentials and state are deleted.
- [ ] Repositories remain clean.
- [ ] Final deployed smoke remains separate and is run only after approved deployment.

## 19. Failure report template

For each failure, record:

```text
Phase:
Timestamp (UTC):
Client and version:
CoinVault commit/image:
OH Auth version:
go-go-mcp version:
Public issuer:
Public resource (safe to record):
Expected behavior:
Observed status/error:
Relevant sanitized headers:
Relevant sanitized server log lines:
Credential material removed: yes/no
Reproduction command with secrets removed:
Suspected boundary:
Next smallest diagnostic action:
```

Do not continue to later phases while an earlier boundary remains unexplained.

## 20. Decision records

### Decision: Test transport before OAuth

- **Context:** MCP, HTTP routing, OAuth discovery, browser identity, and tool policy can fail independently.
- **Options considered:** start directly in ChatGPT; test the full stack locally; stage the boundaries.
- **Decision:** Stage transport, domain tools, local clients, public discovery, OAuth, and ChatGPT in that order.
- **Rationale:** Each failure is attributable to a smaller boundary and can be reproduced without unrelated systems.
- **Consequences:** The procedure has more phases but substantially lower debugging ambiguity.
- **Status:** accepted

### Decision: Keep final deployed smoke narrow

- **Context:** The ticket already has extensive deterministic coverage and publication is protected.
- **Options considered:** broad post-deployment suite; one narrow acceptance flow; no deployed test.
- **Decision:** Run one narrow deployed flow after all local and temporary-public checks pass.
- **Rationale:** Deployment should confirm composition and environment wiring, not repeat library conformance testing.
- **Consequences:** Every negative invariant must remain covered locally before deployment.
- **Status:** accepted

### Decision: Use released dependency tags

- **Context:** Workspace and pseudo-version consumption previously obscured independent consumer behavior.
- **Options considered:** local workspace replacements; pseudo-versions; released tags.
- **Decision:** Acceptance uses OH Auth `v0.0.5` and go-go-mcp `v0.1.0`.
- **Rationale:** Tagged modules are the actual externally consumable artifacts.
- **Consequences:** Any further upstream fix requires a new release before final acceptance.
- **Status:** accepted

## 21. Open questions for the next session

1. Which installed local client provides the clearest Streamable HTTP and OAuth diagnostics: Claude Code, Codex, or another MCP inspector?
2. Is an approved test hostname already available, or should a temporary Cloudflare Tunnel be created?
3. Which GEC test employee and capability set should be used?
4. Which immutable knowledge bundle supplies the fixed read-only acceptance question?
5. Is the RAG process reachable in the same temporary environment for bidirectional audience tests?
6. Which ChatGPT workspace exposes custom MCP connector configuration, and who can remove the connector afterward?

Resolve these questions before starting Phase 4.

## 22. References

- `coinvault/cmd/coinvault/cmds/mcp.go`: CoinVault MCP composition root and OAuth configuration.
- `coinvault/internal/mcpconn/server.go`: canonical `/mcp` validation, authorization-route mounting, and verifier injection.
- `coinvault/internal/mcpoauth/provider.go`: OH Auth, GEC identity, resource policy, claims, and verifier adapter.
- `coinvault/internal/ragresource/server.go`: independent RAG protected-resource metadata and exact-audience enforcement.
- `coinvault/internal/knowledge/evidence.go`: bounded per-session evidence-ledger resolution.
- `coinvault/cmd/coinvault-mcp-smoke/main.go`: local official-SDK MCP smoke client.
- `oh-auth/pkg/httptransport/server.go`: authorization-server metadata and OAuth HTTP endpoints.
- `oh-auth/pkg/oauthserver/engine.go`: authorization transitions and refresh revalidation.
- `go-go-mcp/pkg/embeddable/official_backend.go`: official SDK transport and protected-resource metadata integration.
