---
Title: Extract a composable OAuth authorization server from CoinVault
Ticket: OH-AUTH-001
Status: active
Topics:
    - oauth
    - security
    - architecture
    - golang
    - library
DocType: index
Intent: long-term
Owners: []
RelatedFiles: []
ExternalSources: []
Summary: Design and implement a reusable OAuth authorization-server engine for separate MCP and RAG resource servers.
LastUpdated: 2026-09-01T15:40:00-04:00
WhatFor: Track extraction of CoinVault OAuth mechanics into the independent oh-auth library.
WhenToUse: Use as the landing page for design, implementation, validation, and consumer cutover work.
---

# Extract a composable OAuth authorization server from CoinVault

## Overview

This ticket extracts CoinVault's OAuth authorization-server mechanics into a protocol-neutral Go library for separate MCP and RAG resource servers. The design centers on typed principals, exact resources, canonical scope sets, explicit state transitions, atomic store commits, bounded SQLite persistence, secure consent, and small application adapters.

CoinVault-specific runtime acceptance is tracked separately in CV-MCP-ACCEPT-001 in the CoinVault repository; this ticket remains the source of truth for reusable OH Auth library extraction and conformance.

Research, design, library hardening, deterministic conformance, CoinVault cutover, MCP verifier separation, and independent RAG audience isolation are complete. The post-v0.0.4 APIs still need release tags and the single final deployed acceptance smoke remains pending.

## Key Links

- [Composable OAuth Server Extraction Analysis, Design, and Implementation Guide](design-doc/01-composable-oauth-server-extraction-analysis-design-and-implementation-guide.md)
- [Deferred OWASP Hardening and Higher Assurance Roadmap](design-doc/02-deferred-owasp-hardening-and-higher-assurance-roadmap.md)
- CoinVault-specific MCP/OAuth/ChatGPT acceptance guide moved to [CV-MCP-ACCEPT-001](https://github.com/goldeneagle/coinvault/tree/main/ttmp/2026/09/02/CV-MCP-ACCEPT-001--coinvault-mcp-oauth-and-chatgpt-acceptance-testing)
- [Senior Review of PR 1 Architecture, Implementation, and Review Process](code-review/01-senior-review-of-pr-1-architecture-implementation-and-review-process.md)
- [Investigation Diary](reference/01-investigation-diary.md)
- [Tasks](tasks.md)
- [Changelog](changelog.md)

## Status

Current status: **active**

## Topics

- oauth
- security
- architecture
- golang
- library

## Tasks

See [tasks.md](./tasks.md) for the current task list.

## Changelog

See [changelog.md](./changelog.md) for recent changes and decisions.

## Structure

- design/ - Architecture and design documents
- reference/ - Prompt packs, API contracts, context summaries
- playbooks/ - Command sequences and test procedures
- scripts/ - Temporary code and tooling
- various/ - Working notes and research
- archive/ - Deprecated or reference-only artifacts
