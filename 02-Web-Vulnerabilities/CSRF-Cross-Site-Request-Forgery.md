---
tags: [vuln, web, csrf]
difficulty: medium
status: learning
---

# Cross-Site Request Forgery (CSRF)

> CSRF lives entirely in one fact from [[Browser-Security-Model]]: **the browser attaches cookies to cross-site requests automatically, and the Same-Origin Policy blocks *reading* the response but not *sending* the request.** The attacker never sees the reply — they don't need to. They need the *action* to happen in the victim's authenticated session.

---

## 1. What it actually is
A page the attacker controls causes the victim's browser to send a **state-changing request** to a site where the victim is logged in. The victim's session cookie rides along automatically, so the target processes it as a legitimate, intended action.

```html
<!-- Hosted on evil.com. Victim is logged into bank.com in another tab. -->
<form action="https://bank.com/account/transfer" method="POST" id="f">
  <input type="hidden" name="to"     value="attacker">
  <input type="hidden" name="amount" value="5000">
</form>
<script>document.getElementById('f').submit()</script>   <!-- auto-fires on page load -->
```
Victim opens evil.com → $5000 leaves their account. No credentials stolen; the browser did exactly what browsers do.

## 2. Root cause
Authentication is **ambient** — cookies are sent automatically based on the *destination*, regardless of *which site initiated* the request. The server can't distinguish a request the user *intended* from one a foreign page *triggered*, unless it demands a secret the foreign page cannot obtain. That "unforgeable proof of same-origin intent" is the entire fix.

## 3. Preconditions — all three must hold (if one fails, it's usually not CSRF)
1. **A relevant action** (state change or sensitive read).
2. **Cookie-based session handling** — the request auths purely via automatically-sent cookies (or HTTP Basic/Windows auth).
3. **No unpredictable parameter** the attacker can't know/guess (a CSRF token, or a value only the real UI has).

> **The single most important triage check:** if the app authenticates with an `Authorization: Bearer` header set by JavaScript (not a cookie), there is **usually no CSRF** — the attacker's cross-origin page cannot set that header on a request to your domain. Confirm whether auth is cookie-based first. This kills a lot of invalid "CSRF" reports — see the `triage-validation` skill.

## 4. Exploitation techniques

| Scenario | Technique |
|---|---|
| POST, form-encoded body | Auto-submitting hidden form (above) |
| State change over **GET** (anti-pattern, but common) | `<img src="https://bank.com/transfer?to=x&amount=5000">` — fires with zero JS |
| JSON endpoint | Cross-site `fetch` with `Content-Type: application/json` triggers a **CORS preflight** the target won't approve → blocked. **But** if the server doesn't *enforce* its content type, send the JSON as a form with `Content-Type: text/plain` (a "simple request", no preflight). Always test whether the endpoint *requires* `application/json`. |
| Multipart | `enctype="multipart/form-data"` form |
| **Login CSRF** | Force the victim to log into *your* account → their subsequent activity (saved cards, searches) is recorded under an account you control and later read |
| Token present but weak | Token not tied to the session, reusable across users, only validated when present (drop it entirely), or leaked via `Referer`/URL |

### CSRF token bypass tests (run all of these)
- Remove the token parameter entirely → does it still succeed?
- Submit an empty token.
- Use *another user's* valid token (token not bound to session).
- Change the method (POST protected, but is the token checked on `GET`/`PUT`?).
- Steal the token via any [[XSS-Cross-Site-Scripting]] → CSRF defence defeated entirely.
- Token delivered in a cookie only (double-submit) but a subdomain can set cookies → forge it.

## 5. The fix (layered — each has a gap alone)

| Defence | Strength | How it works / caveat |
|---|---|---|
| **Synchronizer token** (per-session or per-request CSRF token, validated server-side) | **Strong — the primary defence** | Server issues a random token, embeds it in the form/a custom header; validates on every state-changing request. Attacker can't read it (SOP). Must be tied to the session and unguessable. |
| **`SameSite` cookies** | Good default, not complete | `Lax` (modern default) blocks cross-site POST but **not cross-site top-level GET**, and is **site**-scoped so a same-site subdomain (XSS/takeover) bypasses it. See [[Browser-Security-Model]]. |
| **Double-submit cookie** | Medium | Token in a cookie *and* mirrored in a header/body, compared server-side. Weak if any subdomain can set cookies. |
| **Custom-header requirement** (e.g. `X-Requested-With`) | Medium | A cross-site page can't set custom headers without triggering a preflight; good for pure JSON APIs. |
| **`Origin`/`Referer` validation** | Medium | `Origin` is browser-set and reliable *when present*; decide carefully how to treat the absent case (deny can break legit users; allow re-opens the hole). |
| **Re-authentication / MFA / step-up** | Strong | For crown-jewel actions (transfers, password/email change). |

**Correct posture for most apps:** `SameSite=Lax` cookies **+** synchronizer CSRF tokens on all state-changing endpoints **+** step-up auth on the most sensitive actions. Belt and suspenders because each layer has a documented gap.

**Framework reality:** Django, Rails, Spring Security, ASP.NET ship CSRF protection. Real bugs are almost always: it was **disabled "for the API"** (`@csrf_exempt`), the token **isn't validated on some methods**, the API **also accepts a non-JSON content type** so preflight is skipped, or **XSS steals the token**. Grep for the opt-outs.

## 6. Real-world cases
- **YouTube (2008)** — CSRF allowed performing nearly every account action (add videos to favourites, send messages, flag content) on a victim.
- **ING Direct** — CSRF enabled unauthorized fund transfers; a canonical banking example that pushed the industry to tokens.
- **Home routers / IoT (ongoing)** — CSRF to change admin password or DNS settings; old firmware has no `SameSite`, and admin UIs use GET actions.
- **uTorrent (2008)** — CSRF to the local web UI to download/run arbitrary torrents.

## 7. Practice + interview questions

### Practice
- **PortSwigger Academy → CSRF** — all labs (token validation flaws, SameSite Lax bypass, Referer-based defence bypass, token-not-tied-to-session).
- Build a token-less POST endpoint, exploit it with an auto-submitting form, add a synchronizer token, and confirm the attack dies. Then try to bypass your own token with each test in §4.

### Interview questions
- *Explain CSRF using the Same-Origin Policy.* (SOP blocks reading responses, not sending requests; cookies auto-attach → the action fires without the attacker seeing the reply.)
- *Why isn't `SameSite=Lax` complete CSRF protection?* (Cross-site top-level GET still sends the cookie; it's site-scoped so subdomain attacks bypass it; historical Lax+POST 2-minute window.)
- *When is an endpoint NOT CSRF-vulnerable?* (Non-cookie auth like a JS-set bearer header; an unguessable parameter the attacker can't obtain; enforced JSON content-type forcing a preflight.)
- *How does XSS relate to CSRF?* (XSS runs in-origin → it can read the CSRF token and make same-origin requests → defeats every CSRF defence. Fix XSS first.)
- *How does a synchronizer token stop CSRF but a cookie alone doesn't?* (The token must be *read and echoed* by the requester; SOP stops the attacker's page from reading it. A cookie is sent automatically, so it proves nothing about origin intent.)
- *A dev says "we're a JSON API, we don't need CSRF protection." Response?* (Only safe if the server strictly *enforces* `application/json` — otherwise a `text/plain` simple-request form bypasses preflight. Verify enforcement.)

---

**Related:** [[Browser-Security-Model]] · [[XSS-Cross-Site-Scripting]] · [[Session-Management]] · [[Authentication-vs-Authorization]]
