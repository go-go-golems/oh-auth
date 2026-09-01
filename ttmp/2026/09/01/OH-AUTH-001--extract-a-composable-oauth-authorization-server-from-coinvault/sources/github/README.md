# GitHub PR #1 review evidence

This directory contains a reproducible snapshot of inline review comments from [go-go-golems/oh-auth PR #1](https://github.com/go-go-golems/oh-auth/pull/1).

- `pr-1-review-comments.json` — GitHub REST API response captured after the Codex review of head commit `6cf0ff297446be07e5606014681acc8cdc67302f` completed.
- `../../scripts/02-capture-pr-review.sh` — refresh command.

The snapshot contains 15 comments across four reviewed commits:

- five Codex findings on `d2c03e87`;
- five Codex findings on `eea20485`;
- one CodeQL open-redirect annotation on `6df26ff2`;
- four Codex findings on `6cf0ff29`.

The snapshot is evidence, not a statement that comments are still applicable. The accompanying architecture review maps every comment to the current local implementation and marks it fixed, partially fixed, unresolved, or a static-analysis trust-model concern.
