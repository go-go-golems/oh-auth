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
