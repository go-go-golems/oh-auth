#!/usr/bin/env bash
set -euo pipefail

repo="go-go-golems/oh-auth"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ticket_dir="$(cd -- "$script_dir/.." && pwd)"
out="$ticket_dir/sources/github/pr-1-review-comments.json"

mkdir -p "$(dirname -- "$out")"
gh api "repos/$repo/pulls/1/comments" --paginate >"$out"
jq -r '.[] | "ID \(.id) | review \(.pull_request_review_id) | commit \(.original_commit_id[0:8]) | \(.path):\(.original_line // .line)\n\(.body)\nURL: \(.html_url)\n---"' "$out"
