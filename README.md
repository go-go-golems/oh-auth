# oh-auth

`oh-auth` is a composable, protocol-neutral OAuth authorization server library for Go services such as MCP and RAG resource servers.

The library owns OAuth state transitions, PKCE, client registration, consent, authorization-code exchange, refresh-token rotation, resource-bound access tokens, and revocation. Applications provide identity authentication, scope policy, persistence, signing, and resource-specific authorization at narrow interfaces.

## Status

This repository is implementing OH-AUTH-001. The v0.1 design is OWASP-informed, but is not an ASVS certification claim. The package is not yet a stable release.

## Package layout

- `pkg/oauthserver`: protocol-neutral domain types, transition engine, and ports.
- `pkg/oauthresource`: resource-server metadata and bearer-token helpers.
- `pkg/httptransport`: HTTP endpoints and consent UI.
- `pkg/jwttokens`: JWT access-token issuance and verification.
- `pkg/sqlitestore`: bounded durable state transitions using SQLite.
- `pkg/memorytest`: deterministic test doubles and conformance fixtures.

Adapters must depend on `oauthserver`; the core package never imports an application, MCP, RAG, HTTP, database, or JWT implementation.

## Development

All validation intentionally runs outside any workspace file:

```bash
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
make lint
```

The deployed end-to-end smoke test is a single final release-candidate gate and is not run during ordinary development.

## Security boundaries

- OAuth credentials are opaque and stored only as digests by durable stores.
- Issuers are HTTPS origins (no path prefix); loopback HTTP is limited to redirect/resource development URLs.
- Unverified dynamic clients have a bounded idle lease and remain protected while live OAuth state references them.
- Active refresh-family admission is separate from bounded per-family replay history.
- Every grant and token is bound to one exact resource URL.
- PKCE S256 and exact redirect matching are mandatory for public clients.
- Application policy can narrow authority but cannot expand a grant.
- Secrets must be supplied through application configuration, never command-line arguments, logs, or committed files.
- The transport publishes OAuth authorization-server metadata only; it does not claim OpenID Connect support.

See the OH-AUTH-001 design and diary under `ttmp/` for the complete implementation contract and evidence.
