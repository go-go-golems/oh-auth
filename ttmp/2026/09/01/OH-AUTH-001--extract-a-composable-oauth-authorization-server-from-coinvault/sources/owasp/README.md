# OWASP source manifest

Retrieved on 2026-09-01 for the `OH-AUTH-001` design review. `SHA256SUMS` records the downloaded artifacts. Re-run `../../scripts/01-download-owasp-sources.sh` from any directory to refresh them.

## Primary OAuth baseline

- `ASVS-5.0-V10-OAuth-and-OIDC.md`
  - Source: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md
  - Relevant sections: V10.1 Generic OAuth and OIDC Security, V10.3 OAuth Resource Server, V10.4 OAuth Authorization Server, V10.7 Consent Management.
- `OAuth2_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
  - Relevant sections: Essential Basics, PKCE, Token Replay Prevention, Access Token Privilege Restriction, Other Recommendations.
- `WSTG-OAuth-Authorization-Server-Weaknesses.md`
  - Source: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05.1-Testing_for_OAuth_Authorization_Server_Weaknesses
  - Relevant sections: redirect validation, code injection, PKCE downgrade, CSRF, clickjacking, and token lifetime.

## Authorization and workflow

- `Authorization_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
  - Relevant sections: least privilege, deny by default, validate every request, safe failure, logging, tests.
- `Authorization_Regression_Testing_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html
  - Relevant sections: policy matrix, contract-driven validation, CI gating.
- `Transaction_Authorization_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html
  - Relevant sections: significant transaction data, server-side enforcement, allowed transitions, tamper protection, final authorization gate, limited and unique credentials.
- `REST_Security_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
  - Relevant sections: HTTPS, access control, JWT, methods, workflow state, input/content validation, errors, audit, headers, CORS.

## Browser consent surface

- `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  - Relevant sections: synchronizer tokens, Fetch Metadata, SameSite, Origin/Referer validation.
- `Content_Security_Policy_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - Relevant sections: form submission restrictions, framing prevention, policy delivery.
- `HTTP_Headers_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  - Relevant sections: framing, MIME sniffing, referrer, cache, HSTS, CSP, permissions policy.
- `Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  - Relevant sections: safe redirects and URL validation.

## Tokens, keys, secrets, and logs

- `JSON_Web_Token_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
  - Relevant sections: public-key signatures, headers/claims, algorithm and key confusion, trusted key material, revocation, replay.
- `Key_Management_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
  - Relevant sections: key usage and lifecycle, generation, storage, audit, compromise and recovery.
- `Secrets_Management_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
  - Relevant sections: centralized management, handling secrets in memory, audit, lifecycle, TLS, backup, token security, CI/CD.
- `Logging_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
  - Relevant sections: events, attributes, data exclusion, sanitization, verification, availability.

## Input and resource limits

- `Input_Validation_Cheat_Sheet.md`
  - Source: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
  - Relevant sections: allowlist validation, length/range/format/type, server-side validation.
- `API4-2023-Unrestricted-Resource-Consumption.md`
  - Source: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
  - Relevant sections: vulnerable resource classes and How To Prevent.
