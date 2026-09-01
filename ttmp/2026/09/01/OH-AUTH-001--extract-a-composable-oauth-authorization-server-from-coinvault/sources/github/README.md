# GitHub PR #1 review evidence

This directory contains a reproducible snapshot of inline review comments from [go-go-golems/oh-auth PR #1](https://github.com/go-go-golems/oh-auth/pull/1).

- `pr-1-review-comments.json` — GitHub REST API response captured after the Codex review of head commit `6cf0ff297446be07e5606014681acc8cdc67302f` completed.
- `../../scripts/02-capture-pr-review.sh` — refresh command.

The final snapshot contains 26 comments across nine reviewed commits:

- five Codex findings on `d2c03e87`;
- five Codex findings on `eea20485`;
- one CodeQL open-redirect annotation on `6df26ff2`;
- four Codex findings on `6cf0ff29`;
- one Codex finding on `87d5db23`;
- three Codex findings on `92d75d6d`;
- two Codex findings on `dd12cea5`;
- three Codex findings on `4b96e186`;
- two Codex findings on `2dedffa4`.

The implementation continued through `c0544d83`. Per the shipping stop rule, the refresh-digest collision finding from the final reviewed commit was fixed and tested, while optional HTTP 413/415 response categorization was deliberately left as a non-blocking follow-up. No further broad automated review was requested.

The snapshot is evidence, not a statement that comments are still applicable. The accompanying architecture review maps every comment to the current local implementation and marks it fixed, partially fixed, unresolved, or a static-analysis trust-model concern.
