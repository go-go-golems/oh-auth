---
Title: Investigation Diary
Ticket: OH-AUTH-001
Status: active
Topics:
    - oauth
    - security
    - architecture
    - golang
    - library
DocType: reference
Intent: long-term
Owners: []
RelatedFiles:
    - Path: repo://go.mod
      Note: Repository normalization evidence and preserved user toolchain edit
    - Path: ws://coinvault/internal/mcpoauth/provider.go
      Note: Main evidence for concern coupling and transition extraction
    - Path: ws://coinvault/internal/mcpoauth/store.go
      Note: Main evidence for atomic storage behavior
ExternalSources: []
Summary: Chronological evidence, design choices, and delivery record for extracting CoinVault OAuth into oh-auth.
LastUpdated: 2026-09-01T15:40:00-04:00
WhatFor: Preserve how the extraction boundary and composable API were derived from CoinVault, go-go-mcp, the review hardenings, and the new repository.
WhenToUse: Read before implementing or resuming OH-AUTH-001.
---


# Diary

## Goal

Capture the evidence and decisions behind the `oh-auth` extraction design so another engineer can continue without reconstructing the CoinVault OAuth architecture.

## Step 1: Establish the repository boundary and design the reusable engine

This step inspected the new `oh-auth` repository, the full CoinVault provider and store, application identity and scope policy, go-go-mcp's resource-server boundary, the three OAuth review-hardening designs, and current MCP authorization references. The resulting design separates a typed OAuth transition engine from HTTP, SQLite, JWT, identity, MCP, and RAG adapters.

The public API uses clear operation names while preserving rigorous internal rules: each one-time credential advances at most once, every token is bound to one resource, grants only narrow, expected policy outcomes are explicit data, and persistent transitions are atomic and bounded.

### Prompt Context

**User prompt (verbatim):** "I added ./oh-auth as a new repository for that oauth functionality, since we are going to build separate mcp and RAG servers. Create a new docmgr ticket in there for the extraction. Create  a detailed analysis / design / implementation guide that is for a new intern, explaining all the parts of the system needed to understand what it is, with prose paragraphs and bullet point sand pseudocode and diagrams and api references and file references. It should be very clear and technical. Store in the ticket and the nupload to remarkable.

Base your design around a consistent (from a theoretical CS/mathematics point of view) and composable API (don't use maths jargon for the API, make it clear, composable)."

**Assistant interpretation:** Initialize repository-local docmgr state, create a focused extraction ticket, and write a comprehensive implementation guide for a reusable OAuth library whose API is type-safe, transition-oriented, composable, and understandable without mathematical terminology.

**Inferred user intent:** Establish one maintainable OAuth source of truth shared by independent MCP and RAG resource servers rather than duplicating CoinVault-specific authorization code.

### What I did

- Added repository-local `.ttmp.yaml` and initialized `oh-auth/ttmp` with seeded vocabulary.
- Added the `oauth`, `security`, `architecture`, `golang`, and `library` topics.
- Created ticket `OH-AUTH-001` with a design doc and investigation diary.
- Inspected `oh-auth` template state, including module, README, Makefile, workflows, placeholders, and the user's existing toolchain edit.
- Read CoinVault's provider, store, GEC client, capability policy, command composition, tests, and the three review design tickets.
- Read go-go-mcp's `HTTPAuthProvider`, bearer middleware, protected-resource metadata, and principal context integration.
- Consulted the current MCP 2025-11-25 authorization page and the relevant OAuth RFC references.
- Wrote the extraction analysis, package map, generic principal design, transition API, store contracts, SQLite/JWT/HTTP adapters, multi-resource model, phases, tests, risks, and definition of done.

### Why

- OAuth authorization-server mechanics are not specific to MCP or RAG and should not live in either protocol core.
- Copying CoinVault code would copy known coupling and create multiple security implementations.
- A reusable package needs stronger contracts than HTTP handlers calling CRUD methods directly.
- Separate MCP and RAG servers require exact, distinct resource audiences under a consistent issuer and token model.

### What worked

- Existing CoinVault tests and store operations provide a concrete behavior baseline.
- The three review tickets identify the security behavior that must be present before extraction is considered complete.
- A single generic principal-attribute type preserves compile-time application policy while keeping common OAuth identity fields fixed.
- Transition-oriented store methods align atomic persistence with protocol semantics.
- The go-go-mcp integration can become a small one-way adapter from a neutral verified token.

### What didn't work

- The first `docmgr status --summary-only` run from `oh-auth` resolved the parent workspace configuration and reported the CoinVault documentation root:
  - `root=/home/manuel/workspaces/2026-08-28/coinvault-oidc-mcp/coinvault/ttmp`
- That was the wrong ownership boundary for the new repository. I added `oh-auth/.ttmp.yaml`, ran `docmgr init --root ttmp --seed-vocabulary`, and confirmed status now resolves `oh-auth/ttmp`.

### What I learned

- `oh-auth` is currently an unnormalized template: module, command, logging, README, and Makefile still contain `XXX`.
- The user's `go.mod` toolchain update is an unrelated pre-existing change and must be preserved rather than folded into documentation work.
- CoinVault's store already contains valuable consume-once and refresh-replay invariants, but provider mutation ordering and lifecycle need the designed hardenings.
- Supporting multiple exact resource URLs is a small extension that prevents separate MCP and RAG issuers from drifting.

### What was tricky to build

- A universal untyped principal would force runtime casts into security policy, while many generic parameters would make the API difficult to use. The design uses exactly one application-attribute type parameter and fixed common principal fields.
- A small CRUD store interface looks composable but permits partial or invalid changes. The design instead composes around explicit atomic transitions such as `CommitLogin`, `CommitConsent`, `CommitCodeExchange`, and `CommitRefreshRotation`.
- Preparing token output before consuming a code avoids destroying a retryable credential on signer/storage preparation failure; the final conditional commit still ensures one winner under races.
- Identity callback protocols differ substantially. The engine accepts a typed principal after application authentication rather than embedding GEC/OIDC/SAML payload maps.

### What warrants a second pair of eyes

- Validate that one generic principal parameter is ergonomic in real CoinVault and RAG adapters.
- Review code-exchange and login-completion mutation ordering under concurrent callbacks.
- Confirm multi-resource registration and scope metadata satisfy target MCP hosts.
- Verify the chosen pure-Go SQLite driver under WAL, migration, race, and persistent-volume conditions.
- Decide explicitly whether existing refresh grants must survive cutover before implementing any legacy migration.

### What should be done in the future

- Normalize the repository without overwriting the existing toolchain change.
- Implement phases in dependency order, starting with value types and conformance fixtures rather than HTTP.
- Publish oh-auth only after CoinVault and one independent RAG consumer pass with `GOWORK=off`.
- Delete duplicate CoinVault OAuth mechanics after direct cutover.

### Code review instructions

- Start with Sections 6–11 of the design to review invariants, types, transition methods, and store atomicity.
- Then review Sections 13–15 for token and resource-server boundaries.
- Compare the extraction table in Section 20 against `coinvault/internal/mcpoauth/provider.go` and `store.go`.
- Validate implementation with store conformance, transition sequence, race, fuzz, HTTP, token, and cross-resource tests.

### Technical details

- Core target: `pkg/oauthserver` with one type parameter `A` for application principal attributes.
- Adapter targets: `httptransport`, `jwttokens`, `sqlitestore`, `oauthresource`, and test fixtures.
- Dependency rule: `oh-auth` imports neither CoinVault nor go-go-mcp.
- Central grant rule: the engine intersects request, client, resource, principal, consent, and prior grant boundaries.
- Resources are exact URLs; MCP and RAG tokens are not interchangeable.

## Step 2: Validate and publish the design bundle

This step validated the ticket's metadata and relationships, then rendered the design and diary into one reMarkable PDF. A dry run checked the complete input list, output name, table-of-contents depth, and ticket-scoped destination before upload.

The source Markdown remains canonical in `oh-auth/ttmp`; the PDF is a review copy for reading and annotation.

### Prompt Context

**User prompt (verbatim):** (same as Step 1)

**Assistant interpretation:** Complete docmgr validation and deliver the extraction guide to reMarkable.

**Inferred user intent:** Make the architecture package easy to review in depth before implementation begins.

### What I did

- Ran `docmgr doctor --ticket OH-AUTH-001 --stale-after 30`.
- Validated design and diary frontmatter with `docmgr validate frontmatter --suggest-fixes`.
- Checked document size and placeholder comments.
- Ran `remarquee upload bundle --dry-run`.
- Uploaded the design and diary as `OH AUTH Composable OAuth Server Extraction Design.pdf`.

### Why

- Docmgr validation ensures a new repository's ticket plumbing and vocabulary are internally consistent.
- Dry-run-first avoids publishing an incomplete or wrongly routed bundle.

### What worked

- Doctor reported `All checks passed`.
- Both frontmatter validations reported `Frontmatter OK`.
- Remarquee reported `OK: uploaded OH AUTH Composable OAuth Server Extraction Design.pdf -> /ai/2026/09/01/OH-AUTH-001`.

### What didn't work

- The first staged documentation check failed with exit code 2:
  - `ttmp/_guidelines/skill.md:32: new blank line at EOF.`
  - `ttmp/_templates/skill.md:55: new blank line at EOF.`
- Both whitespace defects came from freshly generated docmgr scaffolding. I removed the extra terminal blank lines, restaged the documentation, and reran `git diff --cached --check`.

### What I learned

- The 1,826-line design and diary render successfully as one bundle with a depth-two table of contents.

### What was tricky to build

- The upload record can only be written after the first successful upload. The remote bundle therefore needs one final forced refresh after this diary step is added.

### What warrants a second pair of eyes

- Confirm wide API snippets and package diagrams are readable on the device.
- Confirm the long table of contents remains navigable rather than overwhelming.

### What should be done in the future

- Replace the remote PDF with `--force` only after material design changes because replacement can remove annotations.

### Code review instructions

- Begin with the executive summary, transition model, package structure, and decision records before reading the full implementation phases.

### Technical details

- Remote directory: `/ai/2026/09/01/OH-AUTH-001`.
- Bundle inputs: extraction design and investigation diary.
- Bundle ToC depth: 2.
