# Changelog

## 2026-09-01

- Initial workspace created


## 2026-09-01

Initialized repository-local docmgr and created an evidence-backed intern guide for a typed, transition-oriented, multi-resource OAuth library extracted from CoinVault.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault/internal/mcpoauth/provider.go — Primary implementation source
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault/internal/mcpoauth/store.go — Primary persistence source


## 2026-09-01

Validated the extraction ticket and uploaded the design plus diary bundle to /ai/2026/09/01/OH-AUTH-001.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md — Published canonical extraction design

## 2026-09-01

Downloaded and checksummed a focused OWASP corpus; amended the design for ASVS Level 2, durable grant revocation, consent management/CSRF, JWT trust, browser headers, deny-by-default resource policy, resource budgets, and WSTG-derived CI tests.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md — Amended architecture and OWASP requirement crosswalk
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/sources/owasp/README.md — OWASP source manifest


## 2026-09-01

Replaced the reMarkable bundle with the OWASP-amended design, diary, and source manifest.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md — OWASP-amended published design

## 2026-09-01

Restored the original extraction architecture as the v0.1 baseline, retained only a small OWASP shipping delta, and moved grant status, user management, ASVS profiles, DPoP/PAR, and expanded governance into a separate deferred roadmap.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md — Streamlined v0.1 design
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/02-deferred-owasp-hardening-and-higher-assurance-roadmap.md — Non-blocking future hardening roadmap


## 2026-09-01

Consolidated deployed smoke into one non-destructive final acceptance target after release-candidate deployment; all development phases use local deterministic tests.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md — Phase 12 and consolidated smoke strategy

## 2026-09-01

Step 7: Normalized oh-auth into a library module, removed template binary/logging/release artifacts, and established oauthserver/oauthresource package roots (commit 12c8af9).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/README.md — Library documentation
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/go.mod — Public module normalization

## 2026-09-01

Step 8: Implemented validated core values, typed transition ports, deterministic memory fixtures, and the complete local OAuth lifecycle (commit 523eeea).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/engine.go — Reusable OAuth transition engine

## 2026-09-01

Step 9: Added pure-Go SQLite, fixed-trust JWT, HTTP transport, and resource-server adapters with focused tests (commit 5e00283).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/sqlitestore/store.go — Durable OAuth state

## 2026-09-01

Step 10: Addressed all five PR #1 review findings in oh-auth and advanced CoinVault to the corrected published pseudo-version.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/httptransport/server.go — Review fixes

## 2026-09-01

Completed the CoinVault cutover to oh-auth and pushed review-fixed dependency updates; deleted duplicate local OAuth provider/store mechanics.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault/cmd/coinvault/cmds/mcp.go — Published oh-auth dependency wiring
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault/internal/mcpoauth/provider.go — Application adapter over oh-auth

## 2026-09-01

Step 11: Replaced dynamically concatenated pruning SQL with fixed statements after CI GoSec reported G202; local test, race, vet, lint, and GoSec checks now pass.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/sqlitestore/store.go — Static SQL allowlist for expiry pruning

## 2026-09-01

Step 12: Closed the second Codex review round with subject-bound refresh revalidation, trusted authorization error redirects, complete limit validation, query-bearing redirect support, and IPv6 loopback support.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/httptransport/server.go — Safe authorization error redirects
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/config.go — Complete operational-limit and URL validation
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/engine.go — Subject binding and trusted redirect validation

## 2026-09-01

Step 13: Reconstructed all PR #1 review rounds, corrected the premature green status, and added a senior systemic architecture/implementation review with reproducible GitHub and SQLite evidence.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/code-review/01-senior-review-of-pr-1-architecture-implementation-and-review-process.md — Intern-oriented review and remediation plan
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/scripts/03-probe-sqlite-boundaries.sh — Reproduces raw credential persistence and stale client activity
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/sources/github/pr-1-review-comments.json — Complete PR inline comment snapshot

## 2026-09-01

Step 14: Closed final PR protocol blockers with recoverable unverified-client capacity, durable revocation failure propagation, origin-only issuers, and removal of the dangling registration Location (commit 1d0f453).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/httptransport/server.go — Registration response no longer advertises missing management
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/engine.go — Exhaustive revalidation and correct revocation errors
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/sqlitestore/store.go — Recoverable client lifecycle and authoritative activity reads

## 2026-09-01

Step 15: Enforced digest-only transaction/consent persistence, one injected clock, expiry-based lifecycle, and authoritative predecessor/successor transition validation (commits 258b629, bf6083b).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/memorytest/store.go — Clocked store aligned to durable semantics
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/transitions.go — Pure atomic transition invariant validators
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/sqlitestore/store.go — Digest-only clocked authoritative durable commits

## 2026-09-01

Step 16: Unified engine/HTTP runtime configuration and hardened trusted redirects, media types, OAuth parameter cardinality, DCR metadata, RSA keys, audit coverage, UTC time, and schema checks (commit 7edaef6).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/httptransport/server.go — Single-source runtime and strict protocol parsing
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/jwttokens/service.go — Reusable RSA key safeguards
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/engine.go — Configuration coherence trusted redirects and audit

## 2026-09-01

Step 17: Added deterministic store/HTTP/resource/fuzz conformance, closed remaining refresh replay/lifecycle/admission/registration/consent defects, pinned CoinVault to final oh-auth c0544d83, and stopped the broad review loop at optional HTTP status polish.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/internal/mcpoauth/provider_test.go — GEC-backed consumer integration
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/httptransport/flow_test.go — Complete local OAuth flow without deployed smoke
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/memorytest/store.go — Final refresh digest collision consistency
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/oauthserver/store_conformance_test.go — Shared memory and SQLite executable contract

## 2026-09-01

Step 18: Published the 5,332-word OH Auth deep-dive project report to go-go-parc (ea39f27).

### Related Files

- /home/manuel/code/wesen/go-go-golems/go-go-parc/Projects/2026/09/01/PROJECT REPORT - OH Auth - A Transition-Oriented OAuth Server for MCP and RAG.md — Durable textbook-style project analysis


## 2026-09-01

Steps 19-20: Adopted oh-auth v0.0.4 in CoinVault and hard-cut go-go-mcp from route-owning HTTPAuthProvider to verifier-only HTTPAuthVerifier.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/internal/mcpoauth/provider.go — Explicit authorization-server mount and MCP verifier adapter
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../go-go-mcp/pkg/embeddable/auth_provider.go — Hard-cut resource-server verifier contract


## 2026-09-01

Steps 21-22: Added verification-only JWT construction, independent OAuth-protected RAG search with bidirectional audience isolation, fixed ScopeSet.Contains, and aligned go-go-mcp to current Glazed/toolchain/security dependencies.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/internal/ragapi/server.go — Protected search API and claim-derived policy
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/internal/ragresource/server.go — Exact-audience RAG middleware
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/jwttokens/service.go — Verification-only resource-server adapter

## 2026-09-01

Step 23: Opened oh-auth PR #4 and go-go-mcp PR #83, confirmed CoinVault PR #13 consumer heads, and prepared the final release/smoke handoff.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/internal/ragapi/server.go — CoinVault PR 13 independent RAG consumer
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../go-go-mcp/pkg/embeddable/auth_provider.go — go-go-mcp PR 83 hard-cut verifier boundary
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/jwttokens/service.go — OH Auth PR 4 release boundary

## 2026-09-01

Step 23 follow-up: Increased CoinVault CI lint timeout after a zero-issue analysis exceeded five minutes; exact head 5cd8634 now has green test/lint/secret checks.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/.github/workflows/lint.yml — Allows complete CI analysis without changing lint policy

## 2026-09-01

Step 24: Resolved OH Auth and go-go-mcp review findings, advanced CoinVault to exact corrected revisions, and verified all five CoinVault review findings remain covered (71a304c, d3b9e26, d4b6cac).

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../coinvault/go.mod — Consume reviewed dependency heads
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/../go-go-mcp/pkg/embeddable/command.go — Preserve custom verifier across CLI defaults
- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/pkg/jwttokens/service.go — Reject malformed verification keys

## 2026-09-02

Step 25: Added the staged CoinVault MCP local, OAuth, ChatGPT, isolation, cleanup, and final-smoke acceptance guide for the next session.

### Related Files

- /home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/oh-auth/ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/design-doc/03-coinvault-mcp-local-oauth-and-chatgpt-acceptance-testing-guide.md — Continuation-ready runtime acceptance procedure
