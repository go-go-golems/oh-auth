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
      Note: OAuth HTTP boundary and consent transport (commit 5e00283)
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
    - Path: repo://pkg/sqlitestore/store.go
      Note: Durable digest-only transition store (commit 5e00283)
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/scripts/01-download-owasp-sources.sh
      Note: Reproducible OWASP source download and checksum workflow
    - Path: repo://ttmp/2026/09/01/OH-AUTH-001--extract-a-composable-oauth-authorization-server-from-coinvault/sources/owasp/README.md
      Note: Evidence manifest used for the OWASP review
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
