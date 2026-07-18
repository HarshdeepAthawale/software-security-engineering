---
tags: [vuln, web, open-redirect]
difficulty: low-alone-high-in-chain
status: learning
---

# Open Redirect

> Low severity alone (often N/A on its own — see [[Vulnerability-Management-and-Triage]]), but a powerful **chain component**: it turns phishing legitimate, and — critically — steals OAuth codes/tokens. Value comes from what it enables.

## The bug
```
https://site.com/login?next=https://evil.com   → redirects to evil.com
```
The app takes a user-controlled URL and redirects to it without validating the destination.

## Where it hides
`redirect`, `next`, `url`, `return`, `returnTo`, `dest`, `continue`, `r`, `callback` params; login/logout flows; `<meta http-equiv=refresh>`; JS `location = param`.

## Bypasses (see `security-arsenal` open-redirect bypass table)
`//evil.com`, `https:evil.com`, `/\evil.com`, `https://site.com@evil.com`, `https://site.com.evil.com`, whitelist-substring tricks, encoded variants, `\/\/`.

## Why it matters — the chains
- **OAuth token/code theft** — a loose `redirect_uri` or an open redirect on an allowed host sends the victim's authorization `code` to the attacker → **account takeover**. → [[OAuth2-and-OIDC]] · [[Chaining-Vulnerabilities]].
- **Believable phishing** — link is genuinely on the trusted domain, then bounces to attacker.
- **SSRF filter bypass** — your server 302s to `169.254.169.254` → [[SSRF-Server-Side-Request-Forgery]].
- **CSP/referrer exfil** — bounce to leak data.

## The fix
- **Allowlist** redirect destinations (relative paths only, or a fixed set of full URLs).
- Reject absolute/external URLs; reject `//` and backslash tricks; validate by parsing, not substring matching.
- For OAuth, exact-match `redirect_uri`.

## Interview
- *Is open redirect a serious bug?* (Alone, usually low/N/A; in a chain — OAuth code theft, phishing, SSRF bypass — it's serious. Severity = what it unlocks.) *Fix?* (Allowlist destinations, relative-only, parse don't substring-match.)

---
**Related:** [[OAuth2-and-OIDC]] · [[SSRF-Server-Side-Request-Forgery]] · [[Chaining-Vulnerabilities]]
