#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ticket_dir="$(cd "$script_dir/.." && pwd)"
out="$ticket_dir/sources/owasp"
mkdir -p "$out"

cheatsheet_base="https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets"
download_cheatsheet() {
  local file="$1"
  curl --fail --silent --show-error --location \
    "$cheatsheet_base/$file" \
    --output "$out/$file"
}

for file in \
  OAuth2_Cheat_Sheet.md \
  Authorization_Cheat_Sheet.md \
  Authorization_Regression_Testing_Cheat_Sheet.md \
  REST_Security_Cheat_Sheet.md \
  Input_Validation_Cheat_Sheet.md \
  Logging_Cheat_Sheet.md \
  Secrets_Management_Cheat_Sheet.md \
  Key_Management_Cheat_Sheet.md \
  JSON_Web_Token_Cheat_Sheet.md \
  Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md \
  Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md \
  HTTP_Headers_Cheat_Sheet.md \
  Content_Security_Policy_Cheat_Sheet.md \
  Transaction_Authorization_Cheat_Sheet.md; do
  download_cheatsheet "$file"
done

curl --fail --silent --show-error --location \
  "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x19-V10-OAuth-and-OIDC.md" \
  --output "$out/ASVS-5.0-V10-OAuth-and-OIDC.md"

defuddle parse \
  "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/" \
  --md | fold -w 120 -s > "$out/API4-2023-Unrestricted-Resource-Consumption.md"

defuddle parse \
  "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses" \
  --md | fold -w 120 -s > "$out/WSTG-OAuth-Authorization-Server-Weaknesses.md"

# Keep downloaded evidence reviewable and compatible with repository whitespace
# gates without changing content. Preserve line breaks and remove only trailing
# spaces/tabs introduced by upstream Markdown or fold wrapping.
python3 - "$out" <<'PY'
from pathlib import Path
import sys

for path in Path(sys.argv[1]).glob("*.md"):
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(line.rstrip(" \t") for line in lines) + "\n", encoding="utf-8")
PY

(
  cd "$out"
  sha256sum -- *.md | sort > SHA256SUMS
)

printf 'Downloaded OWASP sources to %s\n' "$out"
wc -l -c "$out"/*.md
