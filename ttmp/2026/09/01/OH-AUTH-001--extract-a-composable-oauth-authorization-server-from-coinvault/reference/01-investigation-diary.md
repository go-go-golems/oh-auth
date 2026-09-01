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
    - Path: repo://Makefile
      Note: Library-only validation targets
    - Path: repo://README.md
      Note: Replaced template documentation with library contract
    - Path: repo://go.mod
      Note: |-
        Repository normalization evidence and preserved user toolchain edit
        Normalized public module path while preserving toolchain
    - Path: repo://pkg/httptransport/server.go
      Note: |-
        OAuth HTTP boundary and consent transport (commit 5e00283)
        PR #1 RFC DTO, issuer, and form-boundary fixes
    - Path: repo://pkg/httptransport/server_test.go
      Note: Regression coverage for review findings
    - Path: repo://pkg/jwttokens/service.go
      Note: Fixed-trust JWT issuer/verifier (commit 5e00283)
    - Path: repo://pkg/memorytest/store.go
      Note: Deterministic atomic store fixture (commit 523eeea)
    - Path: repo://pkg/oauthresource/doc.go
      Note: Initial resource package boundary
    - Path: repo://pkg/oauthresource/token.go
      Note: Resource-server bearer verification boundary (commit 5e00283)
    - Path: repo://pkg/oauthserver/doc.go
      Note: Initial core package boundary
    - Path: repo://pkg/oauthserver/engine.go
      Note: Core transition ordering and scope reduction (commit 523eeea)
    - Path: repo://pkg/oauthserver/identifiers.go
      Note: Validated identifiers and PKCE (commit 523eeea)
    - Path: repo://pkg/oauthserver/ports.go
      Note: Transition and capability contracts (commit 523eeea)
    - Path: repo://pkg/oauthserver/scopes.go
      Note: Canonical immutable scope sets (commit 523eeea)
    - Path: repo://pkg/sqlitestore/codec_test.go
      Note: Arbitrary principal codec regression
    - Path: repo://pkg/sqlitestore/prune_test.go
      Note: Expired-state capacity regression
    - Path: repo://pkg/sqlitestore/store.go
      Note: |-
        Durable digest-only transition store (commit 5e00283)
        Transactional expiry admission and opaque codec bytes
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/scripts/01-download-owasp-sources.sh
      Note: Reproducible OWASP source download and checksum workflow
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/sources/owasp/README.md
      Note: Evidence manifest used for the OWASP review
    - Path: ws://coinvault/internal/mcpoauth/provider.go
      Note: Main evidence for concern coupling and transition extraction
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

## Step 3: Review the architecture against OWASP

This step downloaded a focused OWASP corpus into the ticket, compared the design against ASVS 5.0 OAuth/OIDC requirements and supporting cheat sheets/testing guidance, and amended both the architecture and implementation plan. The original design was strong on exact audiences, scope narrowing, PKCE, refresh rotation, bounded storage, and explicit transitions, but it did not fully cover authorization-code replay revocation, user-managed grants/consents, consent CSRF/clickjacking, authentication context, or fixed JWT trust material.

The amended design targets applicable ASVS Level 2 behavior and records Level 3 DPoP/mTLS/PAR/confidential-client requirements as an explicit unsupported high-assurance profile. It introduces durable grant IDs/versions so code replay, user revocation, and scope reduction share one composable status mechanism.

### Prompt Context

**User prompt (verbatim):** "can you run this design doc against the OWASP guidelines, downloading them to the sources/ folder of the ticket, and amending the design doc appropriately, and adding links to relevant OWASP docs and sections"

**Assistant interpretation:** Download authoritative OWASP material into the ticket, perform a requirement-by-requirement security review, update the design where controls are absent or ambiguous, and add precise web and local-source references.

**Inferred user intent:** Make OWASP evidence and verification requirements part of the implementation contract before code is extracted into the reusable library.

### What I did

- Searched current official OWASP sources for OAuth, ASVS, resource-server, consent, JWT, workflow, logging, input, and resource-exhaustion guidance.
- Added and ran `scripts/01-download-owasp-sources.sh`.
- Downloaded 17 OWASP documents plus a local manifest into `sources/owasp/` and generated `SHA256SUMS`.
- Reviewed ASVS V10.1, V10.2, V10.3, V10.4, and V10.7 requirement tables.
- Reviewed OAuth2, Authorization, REST Security, JWT, Key/Secrets Management, Logging, Input Validation, CSRF, CSP, HTTP Headers, Transaction Authorization, Authorization Regression Testing, API4:2023, and WSTG OAuth guidance.
- Added an OWASP crosswalk, assurance target, source links, residual risks, and verification matrix to the design.
- Amended core principal, grant, code, refresh, consent, store, JWT, resource-verifier, HTTP, audit, configuration, phases, tests, checklist, and definition-of-done sections.

### Why

- A reusable authorization library needs a verifiable security baseline, not only locally reasoned invariants.
- Several OWASP requirements connect concerns that the original design treated separately: code replay and user revocation both need a durable authorization-grant revocation unit.
- Separate MCP/RAG processes need grant-status propagation if access tokens must become invalid before JWT expiry.

### What worked

- The original exact-resource and scope-intersection model maps directly to ASVS V10.3.1, V10.3.2, V10.4.11, and the OAuth2 privilege-restriction guidance.
- Mandatory S256 PKCE, one-minute codes, code-only response type, and refresh rotation align with ASVS V10.4.3–V10.4.6.
- The three prior review designs align with ASVS V10.4.7 and OWASP API4.
- Transition-oriented APIs align strongly with OWASP REST workflow-state and Transaction Authorization guidance.

### What didn't work

- N/A. All official source downloads, Defuddle extraction, checksum generation, and design edits completed successfully.

### What I learned

- ASVS 10.4.2 requires a correctly bound replayed authorization code to revoke tokens already issued from that code, not only reject the replay.
- ASVS 10.4.9 and 10.7.3 require users to review and revoke grants/consents; narrowing scopes is a natural monotonic extension.
- ASVS 10.7.2 expects consent lifetime disclosure in addition to client/resource/scope information.
- ASVS Level 3 requires sender-constrained access tokens and PAR; a short-lived exact-audience bearer token is not Level 3.
- OWASP WSTG treats consent CSRF and clickjacking as concrete OAuth authorization-server tests.

### What was tricky to build

- Immediate JWT revocation across independent resource servers could have introduced raw-token denylists or tight package coupling. A stable `grant_id` plus monotonic `grant_version` provides a clearer composition point: JWT verification establishes token integrity, then a narrow status reader establishes current grant validity.
- Consent CSRF needs an authorization-server browser binding in addition to the OAuth client's `state`. The design uses an unguessable one-time consent form token bound to a secure `__Host-` browser-flow cookie, with Fetch Metadata/Origin checks as defense in depth.
- OWASP has requirements for several roles. The crosswalk distinguishes what oh-auth enforces, what client/resource adapters must enforce, what is not applicable, and what is deferred Level 3.

### What warrants a second pair of eyes

- Review the operational availability and cache policy for remote grant-status checks.
- Confirm target MCP hosts can tolerate an authorization server that always prompts for unverified DCR clients.
- Validate whether user grant management should be hosted by oh-auth HTTP transport or an application-authenticated UI adapter.
- Review the exact ASVS applicability claim; it is a design target, not certification.
- Confirm the Level 3 profile fails closed until DPoP/mTLS/PAR support exists end to end.

### What should be done in the future

- Refresh the OWASP corpus intentionally and review upstream diffs before changing the crosswalk.
- Implement the machine-readable OWASP/authorization test matrix as a required CI gate.
- Decide the grant-status propagation SLA and account-management host before Phase 5/6 implementation.

### Code review instructions

- Start with design Section 27 and trace every “Amended” row back to Sections 8–19.
- Verify `sources/owasp/SHA256SUMS` with `sha256sum -c`.
- Run the download script only when intentionally refreshing source evidence.
- During implementation, use the WSTG-derived matrix in Section 27.8 as executable negative tests.

### Technical details

- Source manifest: `sources/owasp/README.md`.
- Source refresh script: `scripts/01-download-owasp-sources.sh`.
- Primary checklist: OWASP ASVS 5.0 V10.
- Standard profile target: applicable ASVS Level 2 controls.
- High-assurance gap: sender-constrained tokens, PAR/JAR, and strong confidential-client authentication.

## Step 4: Publish the OWASP-amended review bundle

This step rendered the amended design, investigation diary, and OWASP source manifest as one updated reMarkable bundle. The source manifest makes the remote review copy self-describing without embedding more than 400 KB of third-party source text into the PDF.

A dry run confirmed all three inputs before replacing the prior ticket PDF.

### Prompt Context

**User prompt (verbatim):** (same as Step 3)

**Assistant interpretation:** Deliver the OWASP-reviewed architecture and source index to the existing ticket destination.

**Inferred user intent:** Ensure the reMarkable review copy reflects the security audit rather than the superseded initial design.

### What I did

- Ran a forced dry-run bundle with the amended design, diary, and `sources/owasp/README.md`.
- Replaced `OH AUTH Composable OAuth Server Extraction Design.pdf` in the ticket's reMarkable directory.

### Why

- The original PDF predated the OWASP crosswalk and substantial API/security amendments.
- The manifest provides local filenames, canonical URLs, and section relevance without bloating the bundle with every downloaded source.

### What worked

- Remarquee reported `OK: uploaded OH AUTH Composable OAuth Server Extraction Design.pdf -> /ai/2026/09/01/OH-AUTH-001`.

### What didn't work

- Final whitespace validation initially reported: `changelog.md:43: new blank line at EOF.`
- `docmgr changelog update` had appended an extra terminal blank line. I removed it before staging.
- The first staged-source check then found trailing spaces in upstream/raw and Defuddle-folded OWASP Markdown, including `API4-2023-Unrestricted-Resource-Consumption.md:7: trailing whitespace` and multiple WSTG wrapped lines. I amended the download script to remove only trailing spaces/tabs while preserving content and line breaks, reran it, regenerated `SHA256SUMS`, and reran `git diff --check` successfully.

### What I learned

- The amended 2,000-plus-line design, diary, and source manifest render successfully as one navigable PDF.

### What was tricky to build

- Uploading the complete OWASP corpus would make the review bundle unwieldy. The design links exact online sections, while the compact manifest points to downloaded evidence in Git.

### What warrants a second pair of eyes

- Confirm the expanded OWASP tables remain readable on the device.

### What should be done in the future

- Re-upload only after a material design or OWASP-source refresh, using dry-run and `--force` deliberately.

### Code review instructions

- Use design Section 27 as the security review entry point and the manifest to locate source evidence.

### Technical details

- Remote path: `/ai/2026/09/01/OH-AUTH-001`.
- Bundle contents: design, diary, and OWASP source manifest.

## Step 5: Restore a minimal shipping design and isolate deferred hardening

This step reversed the accidental expansion of the main design into a grant-management/compliance platform. The original extraction design was restored as the baseline, the small OWASP shipping delta was added directly, and all expensive controls were moved into a separate roadmap.

The result keeps source evidence and future ideas without making them prerequisites for v0.1.

### Prompt Context

**User prompt (verbatim):** "ok, then move all the unnecessary additions  to a separate document, and just add the new stuff."

**Assistant interpretation:** Remove nonessential OWASP-driven architecture from the shipping design, preserve it in a dedicated document, and retain only the small additions judged necessary.

**Inferred user intent:** Prevent security research from delaying a focused, reusable first release.

### What I did

- Restored the main design from the pre-OWASP-expansion commit as the baseline.
- Added only consent headers/form-token semantics/lifetime, JWT trust constraints, strict HTTP boundaries, deny-by-default consumer enforcement, and focused WSTG tests.
- Created `design-doc/02-deferred-owasp-hardening-and-higher-assurance-roadmap.md`.
- Moved durable grants/status, user grant management, immediate JWT revocation, browser cookie binding, authentication context, formal ASVS profiles, DPoP/mTLS, PAR/JAR/RAR, confidential clients, and exhaustive governance into the roadmap.
- Kept the downloaded OWASP corpus and crosslinks as reference evidence.

### Why

- The expanded design added substantial persistence, API, UI, and runtime coupling without a current product requirement.
- v0.1 can be secure and shippable without claiming ASVS certification.

### What worked

- The main design returned close to its original size and API shape.
- The roadmap retains adoption triggers and detailed sketches without entering the critical path.

### What didn't work

- The first large exact-text edit failed with `Could not find edits[16] ... The oldText must match exactly including all whitespace and newlines.`
- The final definition-of-done line differed from the expected text. I split the change into smaller exact edits and applied the final section separately.

### What I learned

- OWASP references are most useful here as targeted controls and future crosslinks, not as an automatic implementation backlog.

### What was tricky to build

- Necessary and optional controls were interleaved across the expanded type, store, HTTP, JWT, testing, and definition-of-done sections. Restoring the original baseline first was safer than trying to subtract each addition independently.

### What warrants a second pair of eyes

- Confirm the main design has no accidental references to grant status, user grant UI, authentication context, or ASVS compliance profiles.
- Confirm the roadmap is clearly non-blocking.

### What should be done in the future

- Promote a deferred feature only through a focused ticket with a named requirement and accepted operational cost.

### Code review instructions

- Review main design Section 27 for the complete v0.1 delta.
- Review the roadmap only for future scope and adoption triggers.

### Technical details

- Main design: shipping source of truth.
- Deferred roadmap: non-v0.1 security/compliance ideas.

## Step 6: Consolidate deployed smoke into one final run

This step removed repeated deployed smoke expectations from the implementation phases and replaced them with one final, non-destructive acceptance target after release-candidate deployment. Development continues to use fast local unit, conformance, and integration tests.

The final smoke is an orchestrated happy path across authorization, MCP, and RAG, with one cross-audience rejection. Destructive and exhaustive cases stay out of smoke.

### Prompt Context

**User prompt (verbatim):** "Ok, let's update the plan to streamline and consolidate the smoke tests. Ideally we would have a single smoke test at the end, so as not to slow us down too much during development running smoke tests at every turn."

**Assistant interpretation:** Make deployed smoke a single end-of-project gate and keep development validation local and deterministic.

**Inferred user intent:** Preserve confidence without repeatedly paying deployment, browser-login, relinking, and host-interaction costs.

### What I did

- Added Phase 12 for one `make smoke-final` run.
- Clarified that Phases 0–11 use no deployed smoke tests.
- Defined one compact orchestrator covering discovery, 401, DCR, MCP PKCE/call/refresh, RAG PKCE/call, and cross-audience rejection.
- Explicitly excluded replay, revocation, capability mutation, expiry waiting, key rotation, rate/capacity exhaustion, concurrency, outage injection, and exhaustive OWASP tests.
- Reclassified both-host checks and operational/security exercises as release/manual activities only when relevant.
- Updated the task wording and deferred roadmap accordingly.

### Why

- Smoke tests should prove deployed composition, not duplicate deterministic protocol/security suites.
- Destructive smoke steps create relinking work and can affect shared state.

### What worked

- The plan now has one clear smoke command and one final execution point.
- Every broad negative case still has an explicit local or operational test tier.

### What didn't work

- `git diff --check` reported `changelog.md:61: new blank line at EOF.` after the two docmgr changelog updates. I removed the generated terminal blank line before staging.

### What I learned

- A single orchestrator can cover both separate resources without turning every implementation phase into a deployment exercise.

### What was tricky to build

- Cross-resource isolation requires two grants, but it can still be one smoke invocation and one report. The smoke remains compact by using one read-only operation per resource and one refresh total.

### What warrants a second pair of eyes

- Confirm the final smoke can obtain browser consent with minimal human interaction and never writes credentials to artifacts.
- Confirm one representative MCP host is sufficient for routine final smoke while both real hosts remain conditional release checks.

### What should be done in the future

- Keep new negative/security cases in deterministic suites unless a specific deployed wiring risk proves they belong in the final smoke.

### Code review instructions

- Review Phase 12 and Testing Strategy 19.7 together.
- Verify no earlier phase mentions a deployed smoke requirement.

### Technical details

- Final command contract: `make smoke-final SMOKE_CONFIG=/secure/path/smoke.yaml`.
- Target duration: minutes, excluding unavoidable human login/consent.
- Smoke credentials are disposable and never logged or persisted as artifacts.

## Step 7: Normalize the oh-auth repository

This step converted the generated template into a library-shaped repository before adding OAuth behavior. The module path now matches the intended public import path, the placeholder binary and generated logging scaffolding are gone, and the repository no longer advertises a binary release that it cannot build.

The checkpoint establishes a clean dependency boundary for the implementation phases: `pkg/oauthserver` and `pkg/oauthresource` exist as the initial public package roots, while adapters will be added beneath those boundaries rather than around template artifacts.

### Prompt Context

**User prompt (verbatim):** "Let's implement4 the ticket, commit at appropriate intervals and keep a detailed diary as you work (using the diary format from the skill). Print out a brutalist work slip with the plan / different phases for the ticket. then before stsarting a phase, plrint a split about the phase, and print one when the phase is done."

**Assistant interpretation:** Implement OH-AUTH-001 incrementally, commit each meaningful phase, maintain the ticket diary, and print plan/start/completion slips for every phase.

**Inferred user intent:** Make the extraction auditable and resumable while getting working code rather than only a design.

**Commit (code):** 12c8af9 — "chore: normalize oh-auth module"

### What I did

- Printed the six-phase implementation plan slip.
- Printed the Phase 1 start and completion slips.
- Changed `go.mod` to `github.com/go-go-golems/oh-auth` and ran `GOWORK=off go mod tidy`.
- Replaced the template README with the library purpose, package boundaries, security boundaries, and development commands.
- Removed the empty `cmd/XXX`, placeholder package files, logcopter generation, GoReleaser binary configuration, and release workflow.
- Simplified the Makefile to library checks and retained an intentionally failing `smoke-final` placeholder until the final integration phase.
- Added package roots at `pkg/oauthserver` and `pkg/oauthresource`.

### Why

- The generated binary/release setup was unrelated to a reusable library and retained `XXX` placeholders.
- `GOWORK=off` must resolve the module as a consumer would, without workspace-only assumptions.
- Removing the placeholder smoke target later is safer than allowing a false passing release gate.

### What worked

- `GOWORK=off go mod tidy` completed successfully.
- `GOWORK=off go test ./... -count=1` passed.
- The pre-commit test and lint hooks passed.
- The repository no longer contains `XXX` in build/release configuration.

### What didn't work

- A tool invocation initially sent a shell command to the file-writing tool and failed validation: `Validation failed for tool "write": path: must have required properties path, content`. The command was rerun with the shell tool and succeeded.
- The first exact edit for removing the logcopter dependency did not match because `go.mod` had `// indirect`; the second edit used the exact text and succeeded.

### What I learned

- The template's indirect dependency graph was retained solely by the logcopter tool requirement; removing the tool and running `go mod tidy` cleaned it up.
- A library-only project should not retain an empty executable or binary-oriented release workflow.

### What was tricky to build

- Normalization had to remove template identity without touching the pre-existing `toolchain go1.26.7` choice. The module declaration and dependency cleanup were changed, but the toolchain line was preserved exactly.

### What warrants a second pair of eyes

- Confirm deleting the template release workflow is appropriate for the eventual library publication process.
- Confirm the public package paths remain compatible with the design before implementation code is added.

### What should be done in the future

- Add actual package documentation and APIs before publishing a version.
- Replace the intentionally failing `smoke-final` placeholder with the final orchestrator only after deployed integration exists.

### Code review instructions

- Start with `go.mod`, `README.md`, `Makefile`, and `.github/workflows/push.yml`.
- Search for `XXX`, `logcopter`, and `goreleaser` outside ticket evidence.
- Validate with `GOWORK=off go test ./... -count=1` and `GOWORK=off golangci-lint run -v`.

### Technical details

- Module: `github.com/go-go-golems/oh-auth`.
- Public roots: `pkg/oauthserver`, `pkg/oauthresource`.
- Checkpoint commit: `12c8af9962afbf5be4a9decff471af449860bbdd`.

## Step 8: Implement validated core values and transition ports

This step created the first working OAuth domain instead of leaving the repository as a shell. The core package now validates identifiers and PKCE, canonicalizes scope sets, models typed principals and resource-bound state, and exposes transition-oriented storage and capability interfaces.

A deterministic in-memory store and fixture set make the core testable without HTTP, SQLite, JWT libraries, or application dependencies. The engine exercises the complete local lifecycle from dynamic registration through consent, code exchange, refresh rotation, and revocation.

### Prompt Context

**User prompt (verbatim):** (same as Step 7)

**Assistant interpretation:** Begin implementing the ticket according to the staged plan, committing meaningful phases and documenting the implementation journey.

**Inferred user intent:** Establish secure reusable OAuth mechanics with executable tests before wiring real adapters or consumers.

**Commit (code):** 523eeea — "feat: add OAuth core transitions"

### What I did

- Added `pkg/oauthserver` value types for identifiers, exact URLs, scopes, PKCE, principals, resources, clients, consent, authorization codes, and refresh grants.
- Added canonical sorted/deduplicated `ScopeSet` operations with copy-on-read values.
- Added `Config`, secure defaults, state capacity/retention policy, static resource registry, typed OAuth errors, clocks, crypto secrets, and audit ports.
- Defined transition-oriented `Store[A]`, token, scope-policy, revalidation, and secret interfaces.
- Implemented `Engine[A]` operations: `RegisterClient`, `BeginAuthorization`, `CompleteLogin`, `ConsentView`, `DecideConsent`, `ExchangeCode`, `Refresh`, and `Revoke`.
- Added `pkg/memorytest` deterministic store and fixtures.
- Added unit tests for scope immutability, PKCE S256, the complete OAuth lifecycle, wrong-verifier retry, refresh rotation, and revocation.

### Why

- The design requires application identity and policy to remain outside a protocol-neutral core.
- Preparing access/refresh output before atomic code or refresh commits prevents failures from consuming usable credentials.
- The memory store gives a fast executable contract for later SQLite conformance.

### What worked

- `GOWORK=off go test ./... -count=1` passed.
- `GOWORK=off go test -race ./... -count=1` passed.
- `GOWORK=off go vet ./...` passed.
- The pre-commit test and lint hooks passed after the final code adjustment.
- Wrong PKCE verification did not consume the authorization code; the correct verifier subsequently exchanged it.

### What didn't work

- The first commit attempt was rejected by the pre-commit lint hook with:
  - `pkg/oauthserver/scopes.go:89:6: function min has same name as predeclared identifier`
  - `pkg/oauthserver/identifiers.go:51:19: S1002: should omit comparison to bool constant, can be simplified to !u.IsAbs()`
- Renamed `min` to `minInt` and simplified the boolean expression, then reran the commit successfully.
- The initial test compile also reported `code.ConsumedAt undefined`; the missing field was added to `AuthorizationCodeRecord` before rerunning tests.

### What I learned

- The store contract must expose reads separately from atomic commits so wrong bindings can be checked without consuming state.
- Refresh replay semantics require explicit consumed/revoked timestamps in stored records, even if the public design examples omit lifecycle bookkeeping fields.

### What was tricky to build

- The authorization code is returned only through a redirect, while the store must receive only its digest. The engine therefore keeps the raw generated code locally, stores the digest, and constructs the redirect only after the atomic consent commit succeeds.
- Scope reduction occurs at login and again at refresh. The policy returns availability, but the engine performs all intersections.

### What warrants a second pair of eyes

- Review whether the current typed identifier character sets are sufficiently strict for all OAuth endpoint inputs.
- Review the memory store's use of `time.Now()` for consumed timestamps; production stores need a consistent clock/transaction-time policy.
- Review refresh replay handling and the exact error classification before implementing SQLite.

### What should be done in the future

- Add a shared store conformance suite and SQLite implementation.
- Replace the fixture token service with fixed-algorithm JWT issuance and verification.
- Add HTTP parsing and consent transport tests around these transition contracts.

### Code review instructions

- Start with `pkg/oauthserver/identifiers.go`, `scopes.go`, `ports.go`, and `engine.go`.
- Trace `DecideConsent` through `CommitConsent`, then `ExchangeCode` through `CommitCodeExchange`.
- Validate with `GOWORK=off go test ./... -count=1`, `GOWORK=off go test -race ./... -count=1`, and `GOWORK=off go vet ./...`.

### Technical details

- Core package imports only the standard library.
- Raw credentials are generated by `SecretSource`; store-facing records contain `CredentialDigest` values.
- Resource-bound tokens carry one `ResourceID`; refresh scopes are intersected with current policy availability.
- Checkpoint commit: `523eeea97549d2ed60a718924310fcbd2971a079`.

## Step 9: Add SQLite, JWT, HTTP, and resource adapters

This step made the core transitions usable by real services. The SQLite adapter persists only digest-keyed OAuth state and commits code exchange, refresh rotation, and replay-family revocation transactionally. The JWT adapter signs fixed RS256 access tokens with exact issuer/audience/type checks, while the HTTP and resource packages provide metadata, registration, consent, token, revocation, bearer extraction, and challenge helpers.

The adapter checkpoint is still intentionally independent of CoinVault and MCP. That preserves the planned dependency direction and gives the consumer cutover a concrete package API to target.

### Prompt Context

**User prompt (verbatim):** (same as Step 7)

**Assistant interpretation:** Continue the ticket implementation through the durable, token, HTTP, and resource-server adapter phase, with tests and a committed checkpoint.

**Inferred user intent:** Turn the protocol-neutral engine into a reusable service component without coupling it to the existing application.

**Commit (code):** 5e00283 — "feat: add OAuth storage token and HTTP adapters"

### What I did

- Added `pkg/sqlitestore` with pure-Go modernc SQLite, explicit pragmas, schema initialization, digest-keyed state tables, bounded admission, custom principal codecs, and atomic transition commits.
- Added `pkg/jwttokens` with RS256 signing, fixed `at+jwt` type, configured key IDs, deterministic JWKS, reserved-claim protection, and exact issuer/audience/time validation.
- Added `pkg/httptransport` with metadata, DCR, authorization, consent, token, revocation, and identity-callback handlers.
- Added secure HTTP response headers, JSON body limits, strict JSON decoding, method/content-type handling, and a local consent template.
- Added `pkg/oauthresource` bearer extraction, verification delegation, protected-resource metadata, and `WWW-Authenticate` challenge formatting.
- Added SQLite, JWT, HTTP, and resource-focused tests in their respective packages.
- Printed the Phase 3 start and completion slips.

### Why

- SQLite provides a portable durable implementation behind the transition-only store interface.
- JWT issuance and verification are separated from the engine so MCP and RAG can consume the same verified representation.
- Thin HTTP handlers keep protocol parsing at the boundary and leave grant decisions in the engine.

### What worked

- `GOWORK=off go test ./... -count=1` passed.
- `GOWORK=off golangci-lint run -v` passed with 0 issues.
- SQLite replay tests verified that a refresh-family replay revokes the successor family, including the durable commit path.
- JWT tests verified fixed audience isolation and reserved claim rejection.
- HTTP tests verified metadata, registration, no-store, and method/content boundaries.

### What didn't work

- The first SQLite replay implementation updated the family and returned `ErrRevoked` before committing the transaction, so the deferred rollback erased the revocation. The test reported: `family was not revoked: ... RevokedAt:0001-01-01 00:00:00 +0000 UTC`. The replay branch now commits the family revocation before returning the expected error.
- The first HTTP method-boundary test used `GET /path` ServeMux patterns and observed `Allow: GET, HEAD`; method-specific patterns intercepted the request before the handler. Mounting path-only patterns and dispatching methods inside the handler restored exact endpoint control.
- The first lint run reported `store_test.go:19:19: Error return value of store.Close is not checked` and `store.go:501:24: S1002...`; both were fixed before the adapter commit.

### What I learned

- A transition that intentionally returns an error can still need to commit a security side effect; transaction commit/rollback must be reviewed independently from the returned protocol result.
- Go's method-aware `ServeMux` patterns automatically include HEAD behavior, so exact OAuth method contracts require path registration plus explicit dispatch.
- Typed principal codecs must propagate serialization errors rather than silently storing an empty payload.

### What was tricky to build

- SQLite stores generic records containing application principals while keeping the core package database-free. Envelope records isolate principal bytes for the configured codec, and the store limits its connection pool to one writer-oriented connection for predictable SQLite behavior.
- JWT verification must inspect headers before selecting a configured key. The implementation restricts parsing to RS256, requires the configured type and key ID, rejects embedded key material, and checks the exact resource audience after signature verification.

### What warrants a second pair of eyes

- Review the SQLite envelope/schema representation and migration strategy before production use; the first schema initializer is intentionally minimal.
- Review all HTTP redirects and endpoint URL construction, especially deployment behind TLS-terminating proxies.
- Review JWT key rotation configuration and header rejection against the complete WSTG negative matrix.
- Add a fully wired consent browser test rather than only registration/metadata boundary coverage.

### What should be done in the future

- Add shared store conformance tests rather than package-local happy paths.
- Add HTTP flow tests covering consent CSRF/replay, token exchange, and callback integration.
- Replace the temporary single-file adapter implementations with focused files if maintenance pressure warrants it; preserve package dependency direction.

### Code review instructions

- Start with `pkg/sqlitestore/store.go`, then `pkg/jwttokens/service.go`, then `pkg/httptransport/server.go`.
- Trace `CommitRefreshRotation` replay handling and `VerifyAccessToken` header/audience checks.
- Validate with `GOWORK=off go test ./... -count=1`, `GOWORK=off go test -race ./... -count=1`, `GOWORK=off go vet ./...`, and `GOWORK=off golangci-lint run -v`.

### Technical details

- SQLite driver: `modernc.org/sqlite`.
- Signing: RS256 with configured `kid`; default JWT header type `at+jwt`.
- HTTP route mounting uses path-only patterns so handlers enforce exact methods.
- Adapter checkpoint: `5e002834e844b30b2df2e47550dceb9a80f49cb8`.

## Step 10: Address PR #1 review findings across oh-auth and CoinVault

This step closed all five concrete Codex findings on `https://github.com/go-go-golems/oh-auth/pull/1`. The fixes were applied to the reusable library first, then CoinVault was advanced to the corrected oh-auth pseudo-version so the previous extraction ticket consumes the same behavior.

The review fixes protect interoperability and resource bounds at the actual boundaries: RFC dynamic registration uses wire-compatible DTOs, discovery is issuer-stable behind proxies, admission prunes expired rows transactionally, arbitrary principal codec bytes survive storage, and form limits apply before parsing.

### Prompt Context

**User prompt (verbatim):**

```text
Address code review issues: https://github.com/go-go-golems/oh-auth/pull/1 too in the previous ticket\n\n[REMINDER] Output a <summary>...</summary> block at the VERY END of your response. This is mandatory.
```

**Assistant interpretation:** Read PR #1's review comments, implement every requested fix in oh-auth, and update the prior CoinVault extraction ticket/dependency as needed.

**Inferred user intent:** Make the reusable OAuth implementation and its consumer reviewable and safe before continuing feature phases.

**Commits (code):** `6e652b0` — "fix: address OAuth review findings"; `f0688ba` — "test: cover OAuth review fixes"; CoinVault `078648d` — "chore: update oh-auth review fixes"

### What I did

- Read all five inline Codex findings from PR #1.
- Added RFC-compatible registration request/response DTOs using `client_name`, `redirect_uris`, and string-valued `scope`.
- Derived discovery and registration URLs from configured `Config.Issuer`, not request Host/TLS state.
- Applied SQLite expiry pruning inside every transactional admission path and removed expired refresh families before capacity checks.
- Changed principal codec envelope fields from `json.RawMessage` to `[]byte`, preserving arbitrary codec output through JSON base64 encoding.
- Added form content-type checks, `http.MaxBytesReader`, field limits, and configurable array limits before token, consent, and revocation processing.
- Added regression tests for issuer/Host separation, RFC registration shape, expired-state admission, arbitrary codec bytes, and form size limits.
- Updated CoinVault to the corrected oh-auth pseudo-version and preserved the direct adapter cutover.

### Why

- The findings all affected externally observable interoperability or denial-of-service boundaries rather than cosmetic code quality.
- Fixing the library before continuing consumer work prevents CoinVault from encoding known-bad behavior.

### What worked

- All five PR findings have corresponding code changes and regression coverage.
- `GOWORK=off go test ./... -count=1` passed in oh-auth.
- `GOWORK=off go test -race ./... -count=1` passed in oh-auth.
- `GOWORK=off go vet ./...` passed in oh-auth.
- `GOWORK=off golangci-lint run -v` passed in oh-auth.
- CoinVault targeted tests passed with `GOWORK=off` against the published oh-auth pseudo-version.
- The oh-auth fix commit was pushed to `task/coinvault-oidc-mcp`.

### What didn't work

- `GOWORK=on go test ...` failed because this Go toolchain requires an absolute `GOWORK` path: `go: invalid GOWORK: not an absolute path`. The test was rerun with workspace auto-selection and later with `GOWORK=off`.
- `go get github.com/go-go-golems/oh-auth@task/coinvault-oidc-mcp` rejected the slash-containing branch name: `invalid version: version "task/coinvault-oidc-mcp" invalid: disallowed version string`. Fetching the exact pushed commit produced a reproducible pseudo-version instead.
- CoinVault's first pre-push attempt ran its full Dagger/web build and was killed during golangci-lint with `Killed` and `make: *** [Makefile:142: lint] Error 137`; its unit tests passed. The dependency-only follow-up commit was created after targeted validation. A retry with `GOGC=50 GOMAXPROCS=2 git push origin task/coinvault-oidc-mcp` passed the complete CoinVault pre-push suite and pushed successfully.

### What I learned

- ServeMux method patterns can hide handler-level method contracts; path-only mounting is the right choice when exact OAuth methods matter.
- Capacity pruning is part of admission correctness, not merely background maintenance.
- JSON envelopes must treat codec output as opaque bytes unless the public codec contract explicitly promises JSON.

### What was tricky to build

- Expired rows are represented by serialized `ExpiresAt` values inside JSON payloads, while consumed timestamps live in columns. The admission helper deletes by payload expiry and refresh families by their maximum serialized expiry in the same transaction before counting rows.
- Form limits need to cover both the body and repeated fields. Wrapping the body before `ParseForm`, then checking individual field sizes and selected repeated array keys, avoids parsing an unbounded request under a smaller configured policy.

### What warrants a second pair of eyes

- Verify the SQLite payload-expiry comparison remains correct across timestamp formatting and future schema migrations.
- Review whether every consumer should allow HTTP methods with content-type parameters or require the current exact media type.
- Keep the reduced-memory CoinVault push environment in the review runbook if the full Dagger/lint hook becomes memory constrained again.
- Request a fresh PR review against commit `f0688ba` after the branch is pushed.

### What should be done in the future

- Add a shared conformance harness that exercises both memory and SQLite stores for all admission and transition cases.
- Keep the CoinVault dependency pinned to a published oh-auth commit until a release tag exists.
- Replace the temporary `smoke-final` placeholder only during the final smoke phase.

### Code review instructions

- Start with `pkg/httptransport/server.go`, `pkg/sqlitestore/store.go`, and their regression tests.
- Inspect `coinvault/internal/mcpoauth/provider.go` and `cmd/coinvault/cmds/mcp.go` to verify the consumer uses oh-auth rather than the deleted local provider/store.
- Validate oh-auth with `GOWORK=off go test ./... -count=1`, `GOWORK=off go test -race ./... -count=1`, `GOWORK=off go vet ./...`, and `GOWORK=off golangci-lint run -v`.
- Validate CoinVault with `GOWORK=off go test ./internal/mcpoauth ./cmd/coinvault/cmds ./internal/mcpconn -count=1`.

### Technical details

- Review findings addressed: IDs `3907215835`, `3907215845`, `3907215856`, `3907215862`, and `3907215872`.
- oh-auth fix commit: `6e652b0d94657e5abd9306a41f622293bb4dda64`.
- oh-auth regression-test commit: `f0688badba5732e2bfb08a1ca557f36bae5af81e`.
- CoinVault dependency commit: `078648d5d31875f52338855e6cec0e6127968b27`.

## Step 11: Clear the post-review GoSec finding

After the five requested review fixes were pushed, the repository's dependency-scanning workflow exposed one additional security-scan finding in the new pruning helper. The implementation was safe because its table names were locally fixed, but the scanner correctly rejected string-built SQL as an avoidable injection-shaped pattern.

The helper now carries a fixed query literal for each transient table. This preserves the same transactional cleanup behavior while making the SQL allowlist explicit to both reviewers and static analysis.

### Prompt Context

**User prompt (verbatim):** (same as Step 10)

**Assistant interpretation:** Continue closing review-related issues until the pushed oh-auth branch has clean local and CI security validation.

**Inferred user intent:** Avoid leaving the pull request green only on unit tests while a security workflow still fails.

**Commit (code):** a7859a4 — "fix: satisfy SQL security scan"

### What I did

- Read the failed GitHub Dependency Scanning run `33547065100`.
- Confirmed the only finding was `G202 (CWE-89)` at `pkg/sqlitestore/store.go:492`, caused by concatenating a locally selected table name into a DELETE statement.
- Replaced dynamic table concatenation with three fixed SQL query literals.
- Ran the full oh-auth test, race, vet, and GoSec checks.
- Pushed the fix to the PR branch.

### Why

- Static analysis should not need to infer that an internal table-name list is safe.
- Fixed SQL literals are clearer, eliminate the warning, and retain parameterized values for expiry timestamps.

### What worked

- `GOWORK=off go test ./... -count=1` passed.
- `GOWORK=off go test -race ./... -count=1` passed.
- `GOWORK=off go vet ./...` passed.
- `GOWORK=off gosec -exclude=G101,G304,G301,G306,G204 -exclude-dir=.history ./...` passed with `Issues : 0`.
- `GOWORK=off golangci-lint run -v` passed.
- The fix was pushed as `a7859a4`.

### What didn't work

- The first CI run after the five review fixes failed only at GoSec with `G202 (CWE-89): SQL string concatenation` on the pruning helper. No runtime test failed.

### What I learned

- A security scanner finding can be worth fixing even when a dynamic value is internally constrained; removing the pattern makes the invariant executable and reviewable.

### What was tricky to build

- The cleanup loop needed to remain compact without reintroducing dynamic SQL. Keeping the table-specific query and result counter together preserves the loop while making every statement statically visible.

### What warrants a second pair of eyes

- Confirm the next GitHub Dependency Scanning run is green after commit `a7859a4`.
- Keep the SQLite schema and serialized expiry format under review as the store evolves.

### What should be done in the future

- Add a scheduled dependency update workflow or address the repository's unrelated moderate default-branch dependency alert separately.

### Code review instructions

- Review `pkg/sqlitestore/store.go:485-535` and compare its fixed queries with `TestAdmissionPrunesExpiredTransientState`.
- Validate with `GOWORK=off go test ./... -count=1`, `GOWORK=off go test -race ./... -count=1`, `GOWORK=off go vet ./...`, and the repository GoSec command.

### Technical details

- Failed run: `33547065100`.
- Finding: `G202 (CWE-89)` from `"DELETE FROM "+item.table+...`.
- Corrected commit: `a7859a4199ee3ae3c27b83b8332f5290abde941d`.

## Step 12: Address the second PR review round

The next Codex review found five additional correctness gaps after the first fixes. This round closes them without weakening the trust boundary: refresh revalidation must remain tied to the original subject, authorization errors may redirect only after an exact registered redirect is independently validated, all configured limits must be usable, and exact redirect matching must support query components and IPv6 loopback callbacks.

The library and CoinVault consumer now point at the same corrected branch, and the local security suite is green. A fresh GitHub review is requested against the final pushed commit.

### Prompt Context

**User prompt (verbatim):** (same as Step 10)

**Assistant interpretation:** Address the newly reported PR #1 findings as well, including changes needed in the previous CoinVault extraction ticket.

**Inferred user intent:** Continue the review loop until the shared library and its consumer have no known correctness findings.

**Commit (code):** 6df26ff — "fix: close second OAuth review round"; CoinVault dependency update `cf04b4d` — "chore: consume second review fixes"

### What I did

- Bound an eligible refresh revalidation result to the original refresh grant subject; empty or different subjects now fail without consuming the grant.
- Added `Engine.ValidateRedirect` and HTTP authorization-error redirection only after exact client/redirect validation, preserving the client's state for trusted errors.
- Made `Config.Validate` reject every zero/negative operational registration, capacity, retention, and HTTP limit.
- Allowed query components in registered exact redirect URIs while continuing to reject fragments, credentials, and unsafe schemes.
- Corrected IPv6 loopback recognition from `"[::1]"` to the parsed hostname `"::1"`.
- Added regression tests for subject binding, trusted error redirects, all-limit validation, query-bearing redirects, and IPv6 loopback.
- Updated CoinVault to the corrected oh-auth pseudo-version and pushed it through the full reduced-memory pre-push suite.
- Printed the second review-round start slip.

### Why

- Each finding could either break a valid client flow or convert an adapter mistake into cross-account authorization.
- Trusting redirect errors only after a second exact lookup avoids open redirects while still satisfying OAuth client error semantics.

### What worked

- `GOWORK=off go test ./... -count=1` passed.
- `GOWORK=off go test -race ./... -count=1` passed.
- `GOWORK=off go vet ./...` passed.
- `GOWORK=off golangci-lint run --allow-parallel-runners -v` passed with 0 issues; the normal local lock was stale during one attempt.
- `GOWORK=off gosec -exclude=G101,G304,G301,G306,G204 -exclude-dir=.history ./...` passed with 0 issues.
- CoinVault full pre-push validation passed with `GOGC=50 GOMAXPROCS=2`, including build, lint, GoSec, vulnerability scan, and tests.
- Both repositories are clean and their review branches are pushed.

### What didn't work

- A combined local validation attempt reported `Error: parallel golangci-lint is running` even though no active linter process remained. Rerunning with the explicit `--allow-parallel-runners` option passed.
- The first post-fix GitHub review against commit `eea2048` produced the five findings recorded here; the latest commit `6df26ff` was pushed afterward and needs the next review result.

### What I learned

- OAuth error handling needs a separate trusted-redirect validation operation; checking redirect safety only inside the main authorization transition is insufficient when that transition can fail after the client lookup.
- Configuration validation is part of runtime safety: an accepted zero capacity is effectively a deterministic denial of service.

### What was tricky to build

- Query-bearing redirect URIs are safe when compared as exact registered strings, but they cannot pass an origin validator that rejects queries. Splitting generic redirect validation from issuer/resource-origin validation preserves both requirements.
- The revalidation subject check must occur before scope policy, token issuance, or refresh successor persistence, so a malformed adapter result cannot influence any successor state.

### What warrants a second pair of eyes

- Verify the next Codex review checks the latest commit rather than only the earlier `eea2048` snapshot.
- Review trusted error redirect behavior for all failures after client/redirect validation, including temporary login-starter errors.
- Confirm timestamp/query normalization is never introduced around exact redirect comparison.

### What should be done in the future

- Keep the reviewer regression cases in the conformance suite when the in-memory and SQLite stores are unified.
- Address the unrelated moderate dependency alert reported for the oh-auth default branch through normal dependency maintenance.

### Code review instructions

- Review `pkg/oauthserver/engine.go` around `ValidateRedirect` and `Refresh`.
- Review `pkg/oauthserver/config.go` validators and `pkg/httptransport/server.go` authorization error mapping.
- Run `GOWORK=off go test ./... -count=1`, `GOWORK=off go test -race ./... -count=1`, `GOWORK=off go vet ./...`, and GoSec.
- Check CoinVault's `internal/mcpoauth/provider.go` and `go.mod` for consumption of the latest oh-auth commit.

### Technical details

- New review finding IDs: `3907446467`, `3907446479`, `3907446487`, `3907446493`, and `3907446498`.
- oh-auth final review-round commit: `6df26ff2628dddba1f452ec9e76e6a36ccf97d1c`.
- CoinVault consumer commit: `cf04b4d`.

## Step 13: Reconstruct the full PR review and identify systemic gaps

This step revisited every inline finding on PR #1, including comments on superseded commits, and compared them with the current source, tests, design promises, commit history, and CoinVault integration. The resulting senior review is written as a standalone intern-oriented architecture guide rather than a list of isolated comments.

The review corrected an important status error: the prior handoff said the latest Codex review had no findings, but the completed review of head `6cf0ff2` added four unresolved comments. Local probes also found raw transaction and consent credentials in SQLite payloads and a stale `TouchClient` representation, proving that passing CI did not establish the documented storage and lifecycle contracts.

### Prompt Context

**User prompt (verbatim):** "We are stepping in for the junior developer who so far did the actual work on the project. Go over the code review findings (even the older ones) in https://github.com/go-go-golems/oh-auth/pull/1

and go over the local implementation and code, and see what needs to be addressed, what is actually a systemic issue, why things were not caught, etc...

Create  a detailed analysis / code / implementation / architecture review  that is for a new intern, explaining all the parts of the system needed to understand what it is, with prose paragraphs and bullet point sand pseudocode and diagrams and api references and file references. It should be very clear and technical. Store in the ticket and the nupload to remarkable."

**Assistant interpretation:** Perform a senior, evidence-backed review of every PR round and the complete local implementation, distinguish fixed symptoms from systemic defects, explain why normal review and CI missed them, and publish an intern-ready remediation guide.

**Inferred user intent:** Replace premature completion confidence with an accurate technical assessment that a new engineer can use to make the library genuinely shippable.

### What I did

- Captured all 15 PR inline comments in `sources/github/pr-1-review-comments.json` with a reproducible script.
- Mapped each comment to current source and classified it as fixed, partially fixed, unresolved, or a trust-model concern.
- Reviewed every oh-auth package, current tests, CI, README, Makefile, design requirements, diary, commit sizes, and CoinVault consumer wiring.
- Measured current direct package coverage and enumerated untested handlers/transitions.
- Added and ran `scripts/03-probe-sqlite-boundaries.sh` to inspect actual durable payloads and client activity behavior.
- Wrote `code-review/01-senior-review-of-pr-1-architecture-implementation-and-review-process.md` with architecture diagrams, flow explanations, root causes, API sketches, decision records, phased remediation, tests, and file references.
- Added explicit ticket tasks for remediation and conformance work.
- Printed the five-phase shipping plan and Phase 0 start slips.

### Why

- Security review comments need to be generalized into invariants; otherwise each narrow fix exposes the next instance of the same defect.
- A new contributor needs the OAuth roles, state machine, package map, evidence, and implementation sequence before changing security-sensitive code.

### What worked

- `GOWORK=off go test ./... -count=1 -coverprofile=/tmp/oh-auth-cover.out` passed and produced actionable coverage evidence.
- GitHub's REST and GraphQL APIs exposed all comments, reviewed commits, and thread states.
- The SQLite probe reproduced `oauth_authorizations_contains_raw_credential=True`, `oauth_consents_contains_raw_credential=True`, and `touch_visible_through_GetClient=false`.
- The package dependency graph confirmed that `oauthserver` remains application-, HTTP-, database-, JWT-, MCP-, and RAG-independent.

### What didn't work

- The first raw `gh api` response exceeded tool output limits and showed only the tail. Saving the complete JSON under ticket sources and summarizing it with `jq` recovered all 15 comments.
- The previous session's final status was wrong because it inspected an earlier review state before the Codex review for exact head `6cf0ff2` completed.
- The first real reMarkable upload failed after a successful dry run because Pandoc interpreted a literal `\\n` sequence in an older verbatim prompt as a LaTeX command: `! Undefined control sequence. l.4596 ticket\\n`. Wrapping that unchanged verbatim prompt in a fenced text block made it render-safe.

### What I learned

- The strongest local design choices remain worth preserving, but the store's use of transactions was mistaken for authoritative transition validation.
- The design already specified most missing tests; the failure was converting prose acceptance criteria into executable gates.
- Large package-sized commits and non-failing fakes made adversarial dependency behavior difficult to review and impossible to exercise.

### What was tricky to build

- Older GitHub threads remain unresolved even when code changed, and some are not marked outdated because their line survived later patches. Current applicability had to be determined from source behavior, not thread metadata alone.
- The raw-credential defect was hidden by digest primary keys. Only inspecting serialized payload bytes showed that raw transaction and consent handles remained durable.

### What warrants a second pair of eyes

- Review the severity and remediation ordering in Sections 10–19 of the senior review.
- Confirm whether v0.1 should reject issuer paths rather than implement mount-prefix support.
- Confirm the minimal recoverable lifecycle for unauthenticated dynamic clients.

### What should be done in the future

- Never declare an asynchronous reviewer green until its completed result references the exact current head and all current-head comments are classified.
- Convert every security design checklist item into a named deterministic test or explicitly defer/remove it.

### Code review instructions

- Begin with the executive summary and PR chronology in the senior review.
- Run `scripts/03-probe-sqlite-boundaries.sh` to reproduce the two persistence/lifecycle findings.
- Compare design Sections 12, 18, and 19 with the implementation-gap sections of the review.

### Technical details

- PR review counts: 5 findings on `d2c03e8`, 5 on `eea2048`, 1 CodeQL annotation on `6df26ff`, and 4 findings on `6cf0ff2`.
- Direct package statement profile: 48.8% total; HTTP 38.5%, JWT 79.0%, oauthserver 60.2%, SQLite 60.0%, oauthresource 0%.
- No conformance or fuzz test files existed at review time.

## Step 14: Close protocol, lifecycle, and revocation review blockers

This phase addressed the four findings from the final PR review and the related false-success paths identified by the senior review. The implementation deliberately chooses a small v0.1 contract: issuers are origin-only, registration does not advertise unimplemented management, unverified clients expire after bounded idle time, and durable revocation errors remain visible as temporary failures.

The fixes also close nearby instances of the same invariants. Revalidation now handles its enum exhaustively, malformed callback principals are rejected before state lookup, explicit revocation distinguishes an unknown token from a failed store, and successful authorization updates client activity.

### Prompt Context

**User prompt (verbatim):** "finish documenting and uploading, then go through all the items you brought up and make the library solid, without adding unnecessary smoke tests or additional complexity. We want to ship.

commit at appropriate intervals and keep a detailed diary as you work (using the diary format from the skill). Print out a brutalist work slip with the plan / different phases for the ticket. then before stsarting a phase, plrint a split about the phase, and print one when the phase is done.

[REMINDER] Output a <summary>...</summary> block at the VERY END of your response. This is mandatory."

**Assistant interpretation:** Finish publishing the review, then remediate every concrete and systemic issue with minimal coherent designs, deterministic validation, phase commits, diary entries, and printed start/completion slips; do not add deployed smoke complexity.

**Inferred user intent:** Turn the reviewed prototype into a release-worthy reusable OAuth library quickly without papering over security defects or expanding product scope.

**Commit (code):** `1d0f453820bda7fb535ca35afe9a187ffca3f331` — "fix: close OAuth protocol review blockers"

### What I did

- Added a 24-hour default idle TTL for unverified dynamic clients and positive config validation.
- Pruned idle unverified SQLite and memory clients before registration capacity checks while preserving clients referenced by live authorization transactions.
- Updated client activity on authorization and made SQLite `GetClient` read the authoritative activity column.
- Rejected non-root issuer paths instead of retaining incomplete mount-prefix support.
- Removed the unsupported registration-management `Location` header.
- Propagated failed ineligibility-family revocation as `temporarily_unavailable`.
- Made revalidation status handling exhaustive and fail closed.
- Distinguished unknown revocation tokens from infrastructure lookup failures.
- Rejected invalid principal subjects before consuming login state.
- Added focused lifecycle, issuer, registration response, revocation failure, enum, and principal tests.

### Why

- A fixed client count without expiry is a durable unauthenticated denial of service.
- OAuth non-disclosure applies to unknown tokens, not database failures.
- Origin-only issuer support is simpler and safer than claiming path routing that the mux and consent UI do not implement.

### What worked

- `GOWORK=off go test ./... -count=1` passed.
- The pre-commit test and golangci-lint hooks passed with zero issues.
- The lifecycle tests prove idle capacity recovery and preservation of clients with live authorization state.
- Fault-store tests prove revocation failures are visible and malformed revalidation statuses fail closed.

### What didn't work

- N/A. The focused implementation and tests passed on the first full package run.

### What I learned

- The existing `last_used_at` column was suitable for a minimal client lease once reads and writes agreed on it.
- Rejecting issuer paths removes multiple coupled routing bugs with less surface area than adding a prefix abstraction during stabilization.

### What was tricky to build

- Client eviction cannot delete an idle client while a login is in flight because `CompleteLogin` re-reads the client. The SQLite eviction query excludes clients referenced by live, unconsumed authorization records.
- Revocation must preserve RFC non-disclosure for unknown tokens while still surfacing infrastructure errors; sentinel error classification provides that distinction.

### What warrants a second pair of eyes

- Review the default 24-hour unverified client idle TTL and whether CoinVault operations should override it.
- Confirm origin-only issuer support matches deployment configuration.
- Review client activity touch ordering before transaction creation.

### What should be done in the future

- Apply deployment-level request rate limiting to public DCR; database lifecycle is recovery, not a substitute for edge abuse controls.
- Add client management only under a separate RFC 7592 requirement.

### Code review instructions

- Start at `oauthserver.Config.RegistrationPolicy`, `Engine.BeginAuthorization`, `Engine.Refresh`, and `Engine.Revoke`.
- Then inspect `sqlitestore.pruneClientsTx` and `client_lifecycle_test.go`.
- Run `GOWORK=off go test ./... -count=1`.

### Technical details

- Final-review findings addressed: `3907604521`, `3907604555`, `3907604565`, and `3907604576`.
- New fault tests use a store decorator that overrides only refresh lookup/revocation while embedding the full port.

## Step 15: Make durable state truthful and transition commits authoritative

This phase removed the gap between the digest-only storage promise and actual SQLite payloads. Transaction and consent handles are no longer serialized, the engine derives digests from presented credentials rather than store-returned plaintext, and a reproducible database-byte assertion locks the boundary down.

The same phase made time and atomicity coherent. Memory and SQLite stores now use injected clocks, obsolete post-expiry retention knobs are gone, both stores prune by protocol/family expiry, and pure transition validators prevent caller-built successor records from changing client, redirect, state, PKCE, principal, resource, scope, family, generation, or expiry invariants.

### Prompt Context

**User prompt (verbatim):** (same as Step 14)

**Assistant interpretation:** Continue the shipping remediation with minimal state representations, one clock, and atomic invariant checks rather than adding a new persistence architecture.

**Inferred user intent:** Ensure database compromise does not reveal live handles and future adapter/refactor mistakes cannot expand authority through store commits.

**Commits (code):** `258b629c118e68bfef1af4fbbe520359ddb6e43b` — "fix: enforce digest-only state and one clock"; `bf6083b3e0d7c296221df6cd15e782f8a16cb58c` — "fix: make OAuth store transitions authoritative"

### What I did

- Marked transaction and consent raw token fields non-serializable and removed engine dependence on store-returned raw handles.
- Added database-byte assertions for known transaction and consent credentials.
- Added clock injection to SQLite and memory stores and used it for every transition/prune timestamp.
- Made SQLite `Open` remain source-compatible through an optional clock argument.
- Removed unused `ConsumedState` and `RevokedState` configuration rather than pretending SQLite honored it.
- Aligned memory pruning with SQLite: one-time state prunes at protocol expiry and refresh generations prune only when the family expires.
- Added pure validators for login, consent, code exchange, and refresh rotation successor derivation.
- Applied those validators in both memory and SQLite atomic commit paths.
- Added forged successor tests that prove invalid commits do not consume the predecessor and a correct retry still succeeds.

### Why

- Digest primary keys do not provide digest-only storage when raw handles remain in JSON payloads.
- A SQL transaction provides atomic writes but does not prove that successor authority was derived from predecessor authority.
- Configuration fields that do nothing are more dangerous than a smaller explicit lifecycle contract.

### What worked

- The boundary probe changed from raw credentials present/stale activity to `False`, `False`, and `true` respectively.
- `GOWORK=off go test ./... -count=1` passed after each checkpoint.
- `GOWORK=off go test -race ./... -count=1` passed after transition validation.
- Both pre-commit test/lint hooks passed with zero issues.
- Forged consent, code-to-refresh, and refresh-rotation resource bindings are rejected before predecessor consumption.

### What didn't work

- The first transition build failed because a decoded `Principal[A]` variable was reused for encoded `[]byte`: `cannot use encodePrincipal(...) (value of type []byte) as oauthserver.Principal[A] value in assignment`. Renaming the encoded value fixed the type collision.
- Initial authoritative checks exposed incomplete older fixtures: codec consent omitted state/PKCE and the SQLite code fixture omitted state, producing `oauth credential binding mismatch`. The fixtures were corrected to represent valid transitions.

### What I learned

- JSON `json:"-"` fields plus engine digest derivation provide the desired durable boundary without introducing parallel public record hierarchies during stabilization.
- Comparing codec bytes would incorrectly reject randomized encryption codecs. Full principal equality belongs in the generic domain validator (`reflect.DeepEqual`) before encoding.

### What was tricky to build

- Refresh revalidation may legitimately update principal attributes while preserving subject identity, so rotation validates stable subject/resource/client/family and monotonic scopes rather than requiring byte-identical principals.
- Replay handling must revoke and commit a consumed family before returning `ErrRevoked`; normal successor validation must not intercept that security side effect.

### What warrants a second pair of eyes

- Review `transitions.go` field-by-field against each engine successor construction.
- Confirm protocol-expiry pruning supplies enough operational history; redacted audit events remain the intended forensic channel.
- Review use of `reflect.DeepEqual` for application principal attributes with maps/slices.

### What should be done in the future

- If post-expiry forensic retention becomes a named requirement, implement it consistently as archival/audit policy rather than reintroducing partially honored live-state knobs.
- Keep persistence-byte checks in every future durable store conformance suite.

### Code review instructions

- Start with `model.go` raw token JSON tags and the three digest substitutions in `engine.go`.
- Review `transitions.go`, then each corresponding commit method in memory and SQLite.
- Run `scripts/03-probe-sqlite-boundaries.sh`, normal tests, and race tests.

### Technical details

- One-time records remain available until their own expiry; consumed refresh generations remain available until family expiry for replay detection.
- The optional fourth `sqlitestore.Open` argument injects a clock while preserving existing three-argument consumers.

## Step 16: Unify runtime configuration and harden protocol boundaries

This phase removed independent HTTP copies of issuer, resources, token service, and policy. The engine now exposes immutable adapter views, verifies that the token issuer and resource registry match its validated configuration, and gives the HTTP transport one coherent source of runtime truth.

HTTP and JWT hardening stayed focused on protocol-visible ambiguity: typed trusted redirects, client-returned login startup errors, parsed media types, scalar cardinality, body/query separation, bounded DCR arrays, supported metadata, RSA strength, UTC normalization, schema-version fail-closed behavior, and safe audit events for successful authority transitions.

### Prompt Context

**User prompt (verbatim):** (same as Step 14)

**Assistant interpretation:** Remove configuration drift and boundary ambiguity with small API simplifications, not a new server framework or route-prefix subsystem.

**Inferred user intent:** Make the reusable runtime hard to misassemble and interoperability-safe before consumer validation.

**Commit (code):** `7edaef66b4938989a9667be6bc69b40e4bc3ee54` — "fix: unify runtime and harden HTTP boundaries"

### What I did

- Reduced `httptransport.Config` to the engine plus application login starter.
- Added engine views for issuer, resources, tokens, and HTTP policy.
- Added `TokenService.TokenIssuer` and engine issuer-coherence validation.
- Validated configured resources against the injected registry at construction.
- Removed the unused secret-source JTI method; JWT owns JTI generation.
- Added a capability-style `TrustedRedirect` returned only by exact registered lookup.
- Redirected login-starter unavailable/failure outcomes to the trusted client with state.
- Parsed form/JSON media types with `mime.ParseMediaType`.
- Rejected query/body mixing and duplicate scalar OAuth parameters.
- Bounded authorization queries and DCR metadata arrays; rejected unsupported/duplicate grant and response metadata.
- Rejected malformed consent decisions instead of silently interpreting them as denial.
- Enforced valid RSA private keys and 2048-bit minimums in the reusable JWT adapter.
- Normalized all engine timestamps to UTC and made SQLite reject unsupported/corrupt schema version state.
- Added audit events for authorization start, login completion, consent, exchange, refresh, ineligibility revocation, and explicit revocation.
- Added strict HTTP, configuration-coherence, weak-key, schema, and audit tests.

### Why

- Repeating security configuration in every adapter permits metadata, authorization, and tokens to disagree while each constructor succeeds.
- OAuth parameters are bindings; accepting duplicates or query/body ambiguity delegates security semantics to parser ordering.
- CoinVault's RSA check did not protect other library consumers.

### What worked

- Normal tests, race tests, and vet passed.
- Pre-commit test and lint hooks passed with zero issues.
- Parameterized form content types remain interoperable while invalid lookalikes/cardinality are rejected.
- Login startup failure now reaches the exact registered client as `temporarily_unavailable` with original state.

### What didn't work

- N/A. Tests remained green through the runtime/API consolidation.

### What I learned

- Engine adapter views provide most runtime coherence benefits without introducing a larger runtime facade.
- A distinct trusted-redirect type makes the security proof visible to humans and static analyzers while preserving exact URL strings.

### What was tricky to build

- Form parsing normally merges URL query and body values. The token/consent/revoke endpoints now reject any query and validate `PostForm` only, preventing hidden precedence rules.
- Resource-registry coherence must compare exact ID, display name, and canonical scopes at startup without coupling the engine to a concrete registry implementation.

### What warrants a second pair of eyes

- Review whether startup enumeration is acceptable for every intended `ResourceRegistry` implementation.
- Review the `TrustedRedirect` API and CodeQL result on the next exact head.
- Confirm HTTP rejection of token/revoke query parameters matches target clients.

### What should be done in the future

- Add mount-prefix support only if a real deployment requires path-based issuers; origin-only remains explicit v0.1 behavior.
- Introduce schema version 2 only with an actual representation change and migration test.

### Code review instructions

- Review `Engine.New` coherence checks and the reduced `httptransport.Config` first.
- Trace authorization parsing through trusted error redirects and login startup failure.
- Run HTTP strict tests, JWT tests, normal tests, race tests, and vet.

### Technical details

- The SQLite schema remains version 1; startup now rejects zero, duplicate, or unsupported version rows rather than proceeding ambiguously.
- `application/x-www-form-urlencoded; charset=UTF-8` is accepted through standards-based media-type parsing.

## Step 17: Add conformance, consume the final library, and stop at the shipping boundary

This phase added the deterministic evidence that was missing from the original implementation: one complete local HTTP flow, shared memory/SQLite behavior, resource-server helpers, parser fuzzing, signer-failure retry, and a real CoinVault GEC-backed flow. It then used exact-head Codex rounds to find and close remaining authority/lifecycle issues without adding deployed smoke tests.

The review loop was stopped deliberately when findings moved from security and operational correctness to optional HTTP response categorization. The final low-cost correctness issue—refresh digest collision behavior in the memory reference store—was fixed and pushed; 413/415 categorization was reverted as non-blocking polish.

### Prompt Context

**User prompt (verbatim):** (same as Step 14)

**Assistant interpretation:** Finish only deterministic conformance and consumer gates needed to ship, use review feedback for real authority/lifecycle defects, and stop before marginal protocol polish expands scope.

**Inferred user intent:** Produce a trustworthy release candidate now, with explicit evidence and no endless automated-review or smoke-test loop.

**Commits (code):** `87d5db23` — "test: add OAuth conformance and complete HTTP flow"; `92d75d6d` — "fix: revoke refresh replay before external work"; `dd12cea5` — "fix: align client lifecycle and OAuth metadata"; `4b96e186` — "fix: separate refresh admission from replay history"; `2dedffa4` — "fix: complete registration and consent contracts"; `c0544d83` — "fix: reject refresh digest collisions in memory store". CoinVault consumer commits: `1e4c4c6`, `00307b2`, and final pin `a1bc163`.

### What I did

- Added shared memory/SQLite conformance for expiry admission, invalid-binding retry, and concurrent final capacity.
- Added complete HTTP DCR, authorization, callback, consent, code, refresh, revoke, and revoked-refresh coverage.
- Added oauthresource bearer, metadata, challenge, duplicate-header, and exact-resource tests.
- Added a bounded parser fuzz target and signer-failure retry proof.
- Added a complete GEC-backed CoinVault provider flow and pinned published oh-auth pseudo-versions with `GOWORK=off`.
- Revoked consumed refresh replay before all fallible external adapters.
- Preserved idle clients referenced by authorization, consent, code, or refresh state.
- Removed unsupported OpenID discovery and advertised token authentication method `none`.
- Separated active refresh-family admission from retained replay rows and bounded generations per family.
- Corrected SQLite envelope JSON paths for consent, code, and refresh expiry indexes/pruning.
- Made DCR extension-tolerant under the existing body bound and added a dedicated client-ID secret method.
- Carried the consent-disclosed authorization end through code exchange to refresh expiry.
- Added refresh digest collision rejection before memory-store predecessor mutation.
- Updated the senior review with the post-remediation outcome and explicit stop rule.

### Why

- Conformance must compare the reference fake and durable adapter; package-local happy paths had allowed them to drift.
- Active-family capacity and retained replay evidence are different resources and cannot share one row-count quota.
- Shipping requires a stop rule: authority, persistence, lifecycle, and interoperability defects block; optional response polish does not.

### What worked

- All oh-auth normal, race, vet, lint, GoSec, govulncheck, and bounded fuzz gates passed.
- Fuzzing executed 40,986 cases in six seconds and found no parser crash.
- Direct coverage increased from 48.8% to 59.2%; HTTP reached 72.7%, oauthresource 66.7%, oauthserver 67.7%, SQLite 64.2%, and JWT 78.6%.
- CoinVault `GOWORK=off` tests/vet and the full pre-push build, lint, GoSec, govulncheck, and test suite passed.
- The database boundary probe reports no raw transaction/consent credentials and visible client touches.
- Both repositories were pushed after their validation hooks passed.

### What didn't work

- The first post-conformance exact-head review found that consumed refresh replay could exit during revalidation before durable family revocation; the replay check moved ahead of every external dependency.
- Subsequent reviews found active refresh rows coupled to retained generations and missing consent/code client-liveness references. The lifecycle model was corrected rather than raising quotas.
- The final review suggested distinct 413/415 statuses and digest-collision consistency. The status work was started but intentionally reverted after the user confirmed diminishing returns; the collision fix was retained.

### What I learned

- Exact-head review was valuable while it found authority/lifecycle defects, but a severity- and invariant-based stop condition is necessary for shipping.
- SQLite envelope tags must be reflected in every JSON extraction path; tests now cover consent, code, and refresh pruning paths directly.
- A disclosed authorization deadline must become stored grant data, not be recomputed from another state's TTL.

### What was tricky to build

- Replay history must remain available for detection without counting every consumed generation as a new active grant. Active current rows now determine admission, while a per-family generation cap bounds history and revokes only that family at the limit.
- Client eviction must account for state across four differently shaped JSON envelopes. Each live stage now participates in the exclusion, with parallel memory semantics.

### What warrants a second pair of eyes

- Review the default `MaxRefreshGenerations` value (16,384) against expected access-token refresh cadence and 30-day family lifetime.
- Review the deliberate decision to return bounded OAuth `400 invalid_request` rather than distinguish optional 413/415 transport statuses.
- Confirm final CoinVault pseudo-version `c0544d83` is the intended release candidate dependency.

### What should be done in the future

- Complete the separate RAG audience-isolation ticket phase.
- Run the already planned single final deployed smoke only after release-candidate deployment; do not add intermediate smoke runs.
- Treat future protocol polish as ordinary backlog unless it changes authority, durability, availability, or target-client interoperability.

### Code review instructions

- Start with `store_conformance_test.go`, `flow_test.go`, and CoinVault `provider_test.go` to understand the executable contract.
- Review refresh replay ordering, active-family admission, generation bound, and client-liveness SQL.
- Validate with normal/race/vet/lint/GoSec/govulncheck and the bounded fuzz command recorded below.

### Technical details

- Final oh-auth code head: `c0544d83ba28c956c8c450702b58362a2bcec658`.
- Final CoinVault consumer head: `a1bc163`.
- Bounded fuzz command: `GOWORK=off go test ./pkg/oauthserver -run='^$' -fuzz=FuzzOAuthValueParsers -fuzztime=5s`.
- No deployed smoke was added or executed.

## Step 18: Publish the architecture deep dive to the Obsidian vault

This step converted the design, implementation diary, senior review, source code, and release evidence into a 5,332-word textbook-style project report. The report teaches the authority model and transition architecture before describing the implementation, then states the exact consumer work still outstanding.

The report was committed independently in the Obsidian vault before consumer implementation resumed, preserving a durable account of the v0.0.4 checkpoint rather than rewriting that checkpoint after later integration work.

### Prompt Context

**User prompt (verbatim):** "First, use the design doc and diary and what you remember and  write a detailed project report for the obsidian vault as a deep dive technical analysis blog post using a textbook writing style (no analogies, see skill).
 Commit and push the bsidian vault when done (go-go-parc vault).

then, continue with OH-AUTH-001 and integrate and refactor and cleanup coinvault, go-go-mcp,rag. commit at appropriate intervals and keep a detailed diary as you work (using the diary format from the skill). Print out a brutalist work slip with the plan / different phases for the ticket. then before stsarting a phase, plrint a split about the phase, and print one when the phase is done."

**Assistant interpretation:** First publish a long-form, evidence-backed technical report to go-go-parc; then resume OH-AUTH-001 through published-version adoption, a hard MCP boundary cutover, independent RAG integration, cleanup, deterministic gates, diary bookkeeping, and printed phase slips.

**Inferred user intent:** Preserve the architecture as durable knowledge while completing the original multi-consumer purpose of the library without compatibility layers or repeated deployed smoke runs.

**Commit (documentation):** `ea39f27e92d9865587feedc2acc9434cedc213b1` — "docs: add OH Auth technical project report"

### What I did

- Read the complete design, complete diary, senior review, implementation source, CoinVault adapter, and go-go-mcp bearer boundary.
- Read the vault project-note exemplar and an existing project-report exemplar.
- Wrote `PROJECT REPORT - OH Auth - A Transition-Oriented OAuth Server for MCP and RAG.md` under `Projects/2026/09/01`.
- Used foundational prose, real code, state/sequence diagrams, exact paths, validation evidence, failure analysis, and no analogies.
- Validated YAML, Mermaid block count, whitespace, line count, and forbidden analogy terms.
- Staged only the new report, committed it, and pushed go-go-parc `main`.
- Printed the five-phase continuation plan.

### Why

- The ticket documents are implementation references; the vault report is a durable teaching narrative for future engineers.
- Publishing before further work preserves an accurate v0.0.4 checkpoint and prevents the report from becoming an unstructured live changelog.

### What worked

- Frontmatter parsed successfully.
- The report contains 708 lines, 5,332 words, and three Mermaid diagrams.
- The go-go-parc repository was clean before and after the isolated commit and push.

### What didn't work

- N/A.

### What I learned

- The implementation story is best organized around authority intersection, exact resources, atomic successor validation, and review-derived invariants rather than commit chronology.

### What was tricky to build

- The report had to distinguish the released library from the unfinished ticket. v0.0.4 was accurately described as a hardened package checkpoint while CoinVault release adoption, MCP ownership separation, RAG integration, and final smoke remained explicit.

### What warrants a second pair of eyes

- Review the report's description of retained refresh generations and client liveness against current store semantics.
- Review the pending-work section after the integration phases complete; it intentionally describes the historical checkpoint at publication time.

### What should be done in the future

- Create a dated follow-up report if the final deployed architecture materially changes; do not silently rewrite the historical v0.0.4 report.

### Code review instructions

- Open the report in Obsidian and follow its source map into `engine.go`, `transitions.go`, `store.go`, and the consumer boundaries.
- Verify commit `ea39f27` contains only the report.

### Technical details

- Vault: `/home/manuel/code/wesen/go-go-golems/go-go-parc`.
- Report: `Projects/2026/09/01/PROJECT REPORT - OH Auth - A Transition-Oriented OAuth Server for MCP and RAG.md`.

## Step 19: Adopt the published v0.0.4 module in CoinVault

CoinVault now consumes the public `v0.0.4` tag instead of the pseudo-version ending at `c0544d83`. This proved that the tagged module contains the hardened library and resolves without workspace replacement.

The phase ran CoinVault's complete pre-push pipeline rather than only the OAuth package tests. The web build, Go build, project linters, GoSec, govulncheck, and all command/internal tests passed.

### Prompt Context

**User prompt (verbatim):** (same as Step 18)

**Assistant interpretation:** Close the published-consumer acceptance criterion before changing interfaces or adding RAG behavior.

**Inferred user intent:** Ensure the release is genuinely consumable rather than relying on a local workspace or unreleased commit.

**Commit (code):** `0745d95` — "chore: adopt oh-auth v0.0.4"

### What I did

- Ran `GOWORK=off go get github.com/go-go-golems/oh-auth@v0.0.4` and `go mod tidy`.
- Ran focused CoinVault OAuth, command, and MCP connection tests plus vet.
- Committed only `go.mod` and `go.sum`.
- Pushed through the complete reduced-memory CoinVault pre-push pipeline.
- Printed P1 start and completion slips.

### Why

- OH-AUTH-001 explicitly requires CoinVault to pass against a published version outside `go.work`.

### What worked

- The Go proxy returned `v0.0.4` with checksum `K/k0OAMuMb4jWpqGyUeBrQg1Uhhg3TJ81fdGBZ4taOo=`.
- CoinVault's complete gate passed with zero lint and GoSec findings and no called vulnerabilities.

### What didn't work

- N/A.

### What I learned

- v0.0.4 includes the complete hardened code through `c0544d83`; the later Makefile release helper is irrelevant to module consumers.

### What was tricky to build

- The full hook invokes a Dagger frontend build and memory-intensive lint analysis. `GOGC=50 GOMAXPROCS=2` retained the previously proven bounded-memory execution path.

### What warrants a second pair of eyes

- Confirm future dependency changes return to a release tag after the new verifier/RAG APIs are released.

### What should be done in the future

- Tag the next oh-auth release after the post-v0.0.4 resource-server API is finalized; CoinVault temporarily needs an exact pseudo-version for that development.

### Code review instructions

- Review only the version/checksum delta in CoinVault `go.mod` and `go.sum`.
- Re-run the focused OAuth flow with `GOWORK=off`.

### Technical details

- Published version: `github.com/go-go-golems/oh-auth v0.0.4`.

## Step 20: Hard-cut go-go-mcp to a resource-server verifier

This phase removed authorization-server route mounting from go-go-mcp's public application auth contract. The replacement `HTTPAuthVerifier` owns bearer validation, protected-resource metadata, and challenge formatting only. CoinVault mounts OH Auth and the GEC callback explicitly in its composition root.

No old interface, alias, route-mounter assertion, or compatibility adapter remains. Built-in development OAuth retains private route ownership through go-go-mcp's internal runtime assembly, while external OIDC and application verifiers do not expose a mount capability.

### Prompt Context

**User prompt (verbatim):** "make sure to kill backwards compatibility and complexity"

**Assistant interpretation:** Make a coordinated breaking change rather than preserving `HTTPAuthProvider` or dynamically detecting legacy route mounters.

**Inferred user intent:** Complete the dependency boundary that motivated OH Auth: MCP is a resource server and must not own application authorization-server routes.

**Additional user prompt (verbatim):** "this was the whole point"

**Commits (code):** go-go-mcp `86254e8` — "refactor: separate MCP verification from auth routes"; go-go-mcp `3c5e06b` — "refactor: hard cut over to HTTP auth verifier"; CoinVault `ab266b8` — "refactor: separate OAuth routes from MCP verification".

### What I did

- Removed `MountRoutes` from the public interface.
- Renamed the public contract to `HTTPAuthVerifier` and its option to `WithHTTPAuthVerifier`.
- Removed the old API entirely.
- Added a private `httpAuthRuntime` that carries an optional built-in development issuer mount function.
- Renamed CoinVault's mount operation to `MountAuthorizationServer`.
- Added an explicit `MountAuthorizationServer func(*http.ServeMux)` to the CoinVault MCP composition config.
- Made GEC OAuth configuration require both the verifier and authorization-server mount capability.
- Updated tests to prove application verifiers own no routes and CoinVault still protects `/mcp` while mounting OAuth explicitly.
- Updated CoinVault to the exact pushed go-go-mcp pseudo-version and passed full gates.

### Why

- Combining issuer routes and resource verification in one interface made MCP middleware an accidental authorization-server composition root.
- A compatibility shim would preserve the invalid ownership model and complicate every future provider.

### What worked

- go-go-mcp focused tests, vet, and lint passed.
- CoinVault focused tests and the complete pre-push build/lint/security/vulnerability/test pipeline passed.
- Principal context injection and built-in auth modes remained covered.

### What didn't work

- The first go-go-mcp compile after factory refactoring failed with `pkg/embeddable/auth_provider_external_test.go:47:15: undefined: provider`; the typed runtime assertion was assigned to `provider` before token validation.
- The first CoinVault `GOWORK=off` compile intentionally failed against the old released go-go-mcp API with errors such as `*Provider does not implement embeddable.HTTPAuthProvider (missing method MountRoutes)`. The pushed go-go-mcp commit was fetched as a pseudo-version before validating the coordinated hard cutover.

### What I learned

- A small internal runtime assembly is sufficient for the embedded development issuer; it does not justify exposing route ownership to production application verifiers.

### What was tricky to build

- The cutover spans two repositories and cannot compile independently between commits. go-go-mcp had to be committed and pushed first, then CoinVault fetched the exact revision and completed its rename/mount changes.

### What warrants a second pair of eyes

- Review all go-go-mcp callers for the removed `WithHTTPAuthProvider` symbol before release.
- Confirm the private embedded development issuer remains intentionally inside go-go-mcp and cannot be selected accidentally in production configuration.

### What should be done in the future

- Release go-go-mcp with an explicit breaking-change note rather than adding aliases.

### Code review instructions

- Start with `pkg/embeddable/auth_provider.go` and `official_backend.go`, then follow CoinVault `mcpconn.NewHandler` and `MCPServeCommand.Run`.
- Search for `HTTPAuthProvider`, `WithHTTPAuthProvider`, and application `MountRoutes`; no production references should remain.

### Technical details

- Final go-go-mcp phase head: `3c5e06bef8c77baa7f343f28b4645746836cb7bc`.
- Final CoinVault phase head: `ab266b8`.

## Step 21: Add an independent OAuth-protected RAG resource

This phase completed the second-resource proof with production-shaped components. OH Auth gained a verification-only JWT adapter so a RAG process needs public keys but never the issuer's signing key. CoinVault's authorization server now registers distinct MCP and RAG resources and applies resource-aware scope policy.

The webchat process exposes a real `POST /api/rag/query` resource when configured. Its middleware verifies the exact RAG audience, requires the RAG query scope, derives document access from signed GEC capability claims and server policy, and rejects request fields that attempt to select authorization.

### Prompt Context

**User prompt (verbatim):** (same as Step 18)

**Assistant interpretation:** Implement the independent RAG consumer and bidirectional audience proof, not merely a token-verification unit test.

**Inferred user intent:** Demonstrate that OH Auth is genuinely reusable across MCP and RAG while keeping their resources and enforcement independent.

**Commits (code):** oh-auth `934e0c5` — "feat: add verification-only JWT adapter"; oh-auth `35f9bb6` — "fix: correct canonical scope membership search"; CoinVault `2d6c890` — "feat: add independent OAuth-protected RAG resource".

### What I did

- Added `jwttokens.NewVerifier(VerificationConfig)` with issuer, token type, public key ring, and clock but no private key or issuance capability.
- Added CoinVault `ragresource` exact-audience middleware, protected-resource metadata, explicit-scope construction, challenge responses, and verified-token context.
- Added `ragapi` with strict bounded JSON input and a real knowledge-service search call.
- Added `coinvault:rag:documents:read` and `coinvault:rag:query` scopes.
- Made the GEC scope policy resource-aware: MCP retains MCP scopes; RAG knowledge capability maps to RAG scopes.
- Added signed `gec_capabilities` claims and derived internal document access from those verified claims.
- Configured the MCP authorization-server process with both exact resource URLs.
- Configured the webchat/RAG process with issuer, exact resource, and verification-only public keys.
- Proved MCP token rejection at RAG, RAG token rejection at MCP, independent authorization flows, RAG refresh audience retention, empty-policy rejection, claim-derived search policy, and request authorization-field rejection.
- Rejected custom application roots for the first RAG OAuth route implementation instead of partially supporting incorrect metadata paths.
- Printed P3 start and completion slips.

### Why

- A separate process must not receive the authorization server's private RSA key merely to validate access tokens.
- A second exact resource is the executable proof that the library is not only a renamed CoinVault MCP provider.
- Document filtering must come from trusted identity and server policy, never model or request arguments.

### What worked

- OH Auth normal/race/vet/lint checks passed for the verifier adapter and scope fix.
- CoinVault focused normal/race/vet/lint checks passed.
- The complete CoinVault pre-push build, lint, GoSec, govulncheck, and test suite passed.
- The complete GEC-backed HTTP flow issues and refreshes both resource grants from one issuer.

### What didn't work

- The first resource integration test failed despite the RAG token visibly containing `coinvault:rag:query`: `validated RAG token = {Subject:employee-1 ... Scopes:coinvault:rag:query offline_access ...}`. This exposed a reversed comparator in `ScopeSet.Contains`; `sort.Find` was comparing collection values to the target instead of target to collection values. The comparator and direct membership regression tests were corrected in `35f9bb6`.
- Renaming the shared key loader first left three command tests calling `loadMCPVerificationKeys`, producing `undefined: loadMCPVerificationKeys`; the tests were hard-cut to `loadOAuthVerificationKeys`.
- Focused lint found `QF1011: could omit type http.Handler from declaration`; the inferred interface type was used before commit.

### What I learned

- Cross-consumer integration exercises public helpers that lifecycle tests may not use. `ScopeSet.Contains` existed throughout v0.0.4 but lacked direct tests and was exposed immediately by resource middleware.
- Verification-only construction is a distinct security capability, not a nullable signing service.
- Resource scopes and document-access scopes are separate layers: the former permits the endpoint, while signed GEC claims plus server policy derive corpus filtering.

### What was tricky to build

- Browser session middleware already protects the webchat application. The independent RAG API must not pass through that cookie/session resolver, so it is mounted in a dedicated outer mux with its own bearer enforcement while all other routes retain existing session authentication.
- One authorization server supports both resources, but each resource exposes its own metadata and verifier. The CoinVault MCP adapter remains fixed to the MCP audience; the RAG process constructs a verifier from public keys and remains unable to issue tokens.

### What warrants a second pair of eyes

- Review the new signed `gec_capabilities` claim and its mapping to document access scopes.
- Review the decision to reject custom webchat roots while RAG OAuth is enabled.
- Review RAG query response fields for the intended public API data-minimization contract.
- Review deployment configuration so the MCP issuer and RAG process use the same public-key ring without copying private material.

### What should be done in the future

- Release the post-v0.0.4 verifier and scope fix, then pin CoinVault to that tag.
- Add more RAG operations only with explicit scope policies; `Protect` intentionally rejects an empty policy.

### Code review instructions

- Begin with oh-auth `jwttokens.NewVerifier`, then CoinVault `ragresource.Server.Protect`, `ragapi.Server.query`, and resource-aware `gecScopePolicy`.
- Run `TestProviderCompletesIndependentMCPAndRAGGrants`, all `ragresource`/`ragapi` tests, and race tests.

### Technical details

- RAG resource endpoint: `POST /api/rag/query`.
- RAG metadata endpoint: `GET /.well-known/oauth-protected-resource`.
- Authorization input accepts only `query` and optional bounded `limit`; unknown fields fail.
- No deployed smoke was added or executed.

## Step 22: Align dependencies, close deterministic gates, and prepare release handoff

This phase completed the cleanup audit across all three repositories. CoinVault contains no duplicate OAuth authorization mechanics outside its identity/policy adapters; go-go-mcp exposes only the hard-cut verifier contract; and RAG enforces strict JSON, exact audience, explicit scopes, and trusted claim-derived document policy.

The validation sweep also repaired go-go-mcp's stale module baseline. Its declared Glazed `v1.0.5` could not compile the current structured-output API outside `go.work`; the module now pins the newest upstream Glazed revision, a current Go toolchain, and a non-vulnerable gRPC release.

### Prompt Context

**User prompt (verbatim):** "update to newest glazed API"

**Assistant interpretation:** Make go-go-mcp independently build against the current upstream Glazed API rather than relying on the workspace checkout or an older release.

**Inferred user intent:** Remove workspace-only dependency behavior before release and keep the hard-cut API on current project conventions.

**Commits (code):** go-go-mcp `03360e4` — "build: adopt current Glazed and security baseline"; CoinVault `25c3723` — "build: align OAuth consumers with current APIs".

### What I did

- Scanned CoinVault for duplicate PKCE, token, DCR, refresh, and JWT mechanics; remaining OIDC code is browser identity/session behavior rather than duplicate OH Auth protocol state.
- Documented `HTTPAuthVerifier` and the absence of a compatibility alias in go-go-mcp's README.
- Updated go-go-mcp from Glazed `v1.0.5` through `v1.4.3` to newest upstream `a7fdfda` (`v1.4.4-0...`).
- Updated go-go-mcp to toolchain Go 1.26.7 and gRPC 1.82.1.
- Added an executable test for the embedded development issuer's local-only return-target sanitizer and documented the validated GoSec redirect sink.
- Added strict `application/json` enforcement to the RAG query endpoint.
- Updated CoinVault to the final go-go-mcp pseudo-version; minimum-version selection also aligned it to newest Glazed.
- Ran normal, race, vet, lint, GoSec, govulncheck, and bounded fuzz gates across the affected repositories.
- Kept deployed smoke disabled.

### Why

- A release candidate that compiles only because `go.work` replaces a stale declared dependency is not independently consumable.
- Newer security tooling reported both a provably sanitized redirect sink and real standard-library/gRPC vulnerabilities; the former needed evidence, while the latter needed dependency/toolchain updates.

### What worked

- go-go-mcp's full `GOWORK=off go test ./...` changed from compile failure to success after the Glazed update.
- go-go-mcp normal tests, focused race tests, vet, lint, GoSec, and govulncheck passed.
- OH Auth normal/race/vet/lint/GoSec/govulncheck passed; bounded fuzzing ran 17,327 executions with 27 new interesting inputs.
- CoinVault focused normal/race/vet/lint passed, followed by the complete pre-push build, lint, GoSec, govulncheck, and all tests.

### What didn't work

- The first independent go-go-mcp run failed with repeated errors such as `undefined: settings.NewStructuredOutputSection` because `go.mod` still declared Glazed `v1.0.5` while workspace builds used a current local checkout.
- The first broad GoSec invocation used a generic exclusion list and reported the repository's pre-existing editor command sinks plus `G710` on the embedded login redirect. The project exclusion intentionally covers user-selected editor commands; the redirect uses `sanitizeReturnTo`, and a direct local-path rejection test plus a narrow `#nosec G710` explanation now records that proof.
- The first govulncheck after updating Glazed found Go 1.26.3 standard-library vulnerabilities and gRPC 1.78.0. Toolchain 1.26.7 and gRPC 1.82.1 removed all called vulnerabilities.

### What I learned

- Workspace substitution can hide a multi-year dependency drift even when focused package tests pass.
- A security suppression should be paired with an executable validation of the sanitizing function, not only a comment.
- Updating a foundational CLI library can legitimately move many indirect dependencies; full independent compilation is the acceptance criterion.

### What was tricky to build

- The latest Glazed revision adds a large transitive graph, so the module delta is larger than the OAuth API change. Pinning exact upstream `a7fdfda` makes the source of that graph explicit and reproducible.
- GoSec's taint engine cannot infer the return-target sanitizer across the redirect sink. The sanitizer accepts only one leading slash followed by neither slash nor backslash; tests cover absolute URLs, protocol-relative URLs, backslash forms, empty/relative inputs, and valid local paths.

### What warrants a second pair of eyes

- Review the newest Glazed pseudo-version and decide whether to replace it with the next release tag before merging go-go-mcp.
- Review go-go-mcp's existing editor-command G702 exclusion separately from OH-AUTH-001.
- Confirm the RAG API's strict JSON response schema and search-hit data minimization before external publication.

### What should be done in the future

- Release OH Auth and go-go-mcp, then replace CoinVault pseudo-versions with those tags.
- Deploy authorization server, MCP, and RAG together and run the one planned final smoke.

### Code review instructions

- Review go-go-mcp `go.mod`, `HTTPAuthVerifier`, and `sanitizeReturnTo` test.
- Review CoinVault `go.mod` and strict RAG query media-type tests.
- Re-run each repository with `GOWORK=off`; do not rely on the workspace.

### Technical details

- Glazed revision: `a7fdfda5e3c6dc5567003d6c695620542fd3936c`.
- go-go-mcp phase commit: `03360e4eb25ea0409ff19c602fca594c33cc9405`.
- CoinVault phase commit: `25c3723`.
- No deployed smoke was added or executed.

## Step 23: Open focused release pull requests and publish the handoff

This phase pushed every repository cleanly, opened focused pull requests for the post-v0.0.4 OH Auth API and the hard-cut go-go-mcp integration, and refreshed the final ticket review bundle. CoinVault PR #13 already carries the matching consumer commits.

The implementation work is complete through deterministic integration. Tagged releases and the single deployed acceptance smoke remain ordered release operations: merge the library and MCP pull requests, tag them, replace CoinVault pseudo-versions, deploy all three processes, then run the one smoke.

### Prompt Context

**User prompt (verbatim):** (same as Step 18)

**Assistant interpretation:** Finish the continuation with auditable PR and documentation handoff rather than running an unapproved deployment smoke.

**Inferred user intent:** Leave the multi-repository work mergeable, reproducible, and ready for controlled release.

### What I did

- Opened oh-auth PR #4 for verification-only JWT and scope membership correctness.
- Opened go-go-mcp PR #83 for the official SDK/auth verifier hard cut and dependency baseline.
- Confirmed CoinVault PR #13 contains the v0.0.4 adoption, MCP boundary cutover, and RAG consumer.
- Validated clean repository states and exact pushed heads.
- Ran docmgr doctor and updated the ticket index, task state, diary, changelog, and related evidence.
- Refreshed the reMarkable ticket bundle with design, senior review, diary, and evidence manifest.
- Printed the P5 start and completion slips.

### Why

- The new resource verifier and hard-cut MCP API need releases before CoinVault can stop using development pseudo-versions.
- Deployment remains controlled by protected publication infrastructure and is not a local code-completion step.

### What worked

- PRs were created at `https://github.com/go-go-golems/oh-auth/pull/4` and `https://github.com/go-go-golems/go-go-mcp/pull/83`.
- All local deterministic gates were green at the pushed heads.
- The final bundle rendered and uploaded to `/ai/2026/09/01/OH-AUTH-001`.

### What didn't work

- N/A.

### What I learned

- The release sequence now has two dependency levels: OH Auth and go-go-mcp must be tagged before CoinVault can replace exact pseudo-versions and become a final deployment candidate.

### What was tricky to build

- go-go-mcp PR #83 contains the official SDK and session/auth foundation that preceded the verifier hard cut; splitting only the last two commits would omit the boundary CoinVault already consumes. The PR therefore presents the coherent branch rather than manufacturing a compatibility branch.

### What warrants a second pair of eyes

- Review OH Auth PR #4's verification-only key contract and `ScopeSet.Contains` fix.
- Review go-go-mcp PR #83 as a breaking API/official SDK transition, not a patch-compatible update.
- Review CoinVault PR #13 deployment flags for distinct MCP/RAG resource URLs and public verification-key distribution.

### What should be done in the future

- Merge and release OH Auth and go-go-mcp.
- Pin CoinVault to those tags and rerun its complete gate.
- Deploy authorization server, MCP, and RAG; run the single final smoke; then check the remaining combined acceptance task.

### Code review instructions

- Review PRs in dependency order: OH Auth #4, go-go-mcp #83, CoinVault #13.
- Do not request another broad automated OH Auth review; use the named deterministic contracts and focused human review.

### Technical details

- OH Auth head: `abc1a63b77a43519cababa101fb24d0415ba370f`.
- go-go-mcp head: `03360e4eb25ea0409ff19c602fca594c33cc9405`.
- CoinVault head: `25c3723a056138b9a2582f0829101d1cfefaa5ae`.
- Final smoke remains intentionally unexecuted.
