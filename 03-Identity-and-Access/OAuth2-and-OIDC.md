---
tags: [identity, oauth, oidc]
difficulty: high
status: learning
---

# OAuth 2.0 & OpenID Connect

> The most-asked identity topic in AppSec interviews, and one of the richest real-world bug areas. Most engineers can *use* "Login with Google" but can't explain what each redirect is doing or how to break it. Being fluent here is a genuine differentiator — and OAuth bugs are frequently **critical** (full account takeover with one click).

---

## 1. First: OAuth ≠ OIDC (get this exactly right)
- **OAuth 2.0 = authorization (delegated access).** "Let this app access my Google Drive files." It issues **access tokens** that grant an app permission to call an API *on your behalf*. OAuth says nothing about *who you are* — it's about *what an app may do*.
- **OpenID Connect (OIDC) = authentication, layered on OAuth.** It adds an **ID token** (a signed JWT with identity claims: `sub`, `email`, `name`) and a `/userinfo` endpoint. "Login with Google" is OIDC.

**Why this distinction causes bugs:** developers use an OAuth *access token* as proof of *identity* ("this token works, so you must be user X"). But an access token only proves *an app has permission* — a token minted for a *different* app can be replayed to impersonate the user. This is the **confused-deputy / token-substitution** bug, and it's common. Identity must come from a *validated ID token*, not an access token.

---

## 2. The four grant types (know when each applies)

| Grant | Use case | Token in browser? | Verdict 2026 |
|---|---|---|---|
| **Authorization Code + PKCE** | Web apps, SPAs, mobile | No (code only) | ✅ **The default for everything** |
| Implicit | Legacy SPAs | Yes (token in URL fragment) | ❌ Deprecated — leaks via history/referer |
| Resource Owner Password | Legacy first-party | n/a | ❌ App handles the password — avoid |
| Client Credentials | Machine-to-machine (no user) | n/a | ✅ For service-to-service only |

The only one you should design with today is **Authorization Code + PKCE**. If you see implicit flow in a review, that's a finding.

---

## 3. The Authorization Code + PKCE flow — know it cold

```
1. User clicks "Log in with Google" on app.com
2. app.com generates:  state = random,  code_verifier = random,
                        code_challenge = SHA256(code_verifier)
3. Browser → Authorization Server (Google):
   GET https://accounts.google.com/o/oauth2/v2/auth
       ?response_type=code
       &client_id=CLIENT_ID
       &redirect_uri=https://app.com/callback
       &scope=openid email profile
       &state=RANDOM                 ← CSRF binding
       &code_challenge=HASH          ← PKCE
       &code_challenge_method=S256
       &nonce=RANDOM2                ← OIDC replay protection (ID token)
4. User authenticates at Google & consents to the scopes
5. Google → Browser → 302 redirect to:
   https://app.com/callback?code=AUTH_CODE&state=RANDOM
6. app.com verifies state matches, then server-to-server:
   POST https://oauth2.googleapis.com/token
       code=AUTH_CODE
       &client_id=CLIENT_ID
       &client_secret=SECRET         ← confidential clients only
       &code_verifier=VERIFIER       ← PKCE proof
       &grant_type=authorization_code
7. Google returns:  access_token, id_token (JWT), refresh_token
8. app.com VALIDATES the id_token (sig, iss, aud, exp, nonce), then
   establishes its own session.
```

**Why each parameter exists (interviewers drill exactly this):**

| Param | Defends against | If missing/unchecked |
|---|---|---|
| **`state`** | CSRF on the OAuth flow | Attacker forces their own `code` into your session → **account linking / login CSRF** (you log in as the attacker, or the attacker's account gets linked to yours) |
| **`code`** (vs a token in the URL) | Token leakage | Implicit flow puts the token in the fragment → browser history, `Referer`, extensions |
| **PKCE** (`code_challenge`/`verifier`) | Authorization-code interception | A malicious app / network intercepts the `code`; without the verifier it's useless — but only if the AS *enforces* it |
| **`nonce`** | ID token replay | An old/stolen ID token can be replayed |
| **`client_secret`** | Client impersonation | Public clients (SPA/mobile) can't hold one → that's *why* PKCE exists |

---

## 4. The bug catalogue (memorise — these are the money bugs)

### 4a. `redirect_uri` validation flaws — the #1 target
If you can make the AS deliver the `code` to a URL you control, you get the victim's account. Test every mutation:

| Attack on `redirect_uri` | Example |
|---|---|
| Weak/partial match | Registered `https://app.com/callback`, AS allows `https://app.com/callback.evil.com` or any path |
| Path traversal / append | `https://app.com/callback/../redirect?url=evil.com` |
| Open redirect on an *allowed* host | `redirect_uri=https://app.com/logout?next=https://evil.com` — valid host, then bounces the code out → [[Open-Redirect]] |
| Subdomain wildcard | `*.app.com` registered + a subdomain takeover or XSS → capture code |
| `@`, `#`, `\`, encoded-slash tricks | `https://app.com@evil.com`, `https://evil.com\.app.com`, `%2f%2e%2e` |
| Second `redirect_uri` param | Parameter pollution — AS validates the first, uses the second |
| Localhost/loopback loosening | Some AS allow any port on `127.0.0.1` |

**How the code gets stolen once redirected:** the `code` lands in the query string of *your* page → you read it from `Referer` (if the callback page loads an external resource), from `window.location`, or the browser navigates straight to your server with `?code=...`.

### 4b. Everything else

| Bug | Mechanism | Impact |
|---|---|---|
| **Missing/ignored `state`** | No CSRF binding | Login CSRF, forced account linking |
| **`state` fixed/predictable** | Not truly random or not tied to session | Same as missing |
| **PKCE not enforced** | AS accepts the exchange without verifying `code_verifier` | Code interception → ATO on mobile/SPA |
| **Access token used as identity** | App reads `access_token` → identifies user | Token from another client impersonates ("confused deputy") |
| **ID token signature unchecked** | Client trusts the JWT blindly | Forge identity → [[JWT-Attacks]] |
| **`aud`/`iss` not validated** | Token minted for a *different* client accepted | Cross-client replay → ATO |
| **`nonce` not checked** | ID token replay | Reuse a captured token |
| **Implicit flow** | Token in URL fragment | Leak via history/referer |
| **Scope upgrade** | Client doesn't verify *granted* scopes vs *requested* | Privilege escalation |
| **Refresh token not rotated / long-lived** | Stolen refresh token = persistent access | Long-term ATO |
| **Pre-account-takeover** | App auto-links OAuth to an existing email without verification | Attacker pre-registers victim's email, victim later "Logs in with Google" into attacker's account |
| **CSRF on the "link account" endpoint** | No `state` on linking flow | Attacker links their social account to victim → logs in as victim |

---

## 5. Exploitation walkthrough — `redirect_uri` → ATO

```
1. Recon: find the OAuth flow, note client_id and the registered redirect_uri.
2. Fuzz redirect_uri: try app.com.evil.com, app.com@evil.com,
   app.com/callback/../open-redirect?u=evil.com, an extra redirect_uri param.
3. Find one the AS accepts that lands the code on infrastructure you control
   (or on an open-redirect that bounces to you).
4. Craft the malicious authorize URL with your redirect_uri and the victim's
   normal client_id/scope.
5. Send it to the victim (they're already logged into Google). One click →
   Google redirects the AUTH_CODE to you.
6. Exchange the code (if PKCE isn't enforced / it's implicit you get the token
   directly) → you now hold the victim's authorization → log in as them.
```

Blind spot to also check: even with a *perfect* `redirect_uri`, an **open redirect or XSS on the callback host** re-opens the whole attack. That's why [[Open-Redirect]] chains to critical here.

---

## 6. The fix (server + client responsibilities)

**Authorization Server:**
- **Exact-string match `redirect_uri`** against pre-registered values. No wildcards, no path flexibility, no substring matching.
- **Enforce PKCE** (S256) — reject exchanges without a valid `code_verifier`.
- Single-use, short-lived (~30–60s) authorization codes; bind the code to the client and PKCE challenge.
- Rotate refresh tokens; detect refresh-token reuse (replay = revoke the family).

**Client (the app):**
- **Always send and strictly validate `state`** (random, tied to the user's session, compared on callback).
- **Validate the ID token fully:** signature against the AS's JWKS, `iss` = expected issuer, `aud` = *your* client_id, `exp`/`nbf`, and `nonce` = the one you sent.
- Use the **ID token** for identity — never the access token.
- Verify *granted* scopes, don't assume requested = granted.
- Prefer **Authorization Code + PKCE**; never implicit.
- No open redirects / XSS on the callback host.
- Verify email ownership before auto-linking an OAuth identity to an existing account.

---

## 7. Real-world cases (study these)
- **"Sign in with Apple" (2020, CVE-2020-...)** — Apple's AS would issue a valid ID token for *any* email the attacker specified; apps that trusted the ID token's email without checking `aud`/issuer specifics granted full ATO on any account. ~**$100,000** bounty. The definitive ID-token-validation lesson.
- **Facebook / Microsoft / Booking.com `redirect_uri` writeups** — repeated ATOs from loose redirect validation and open-redirect chains; excellent disclosed reports to read.
- **Pre-account-takeover research (Sudhanshu Rajbhar / others)** — auto-linking OAuth to unverified emails → attacker owns accounts before the victim signs up.
- **GitLab, Shopify, Slack** — many disclosed `state`/CSRF and scope bugs in social login/linking flows.

---

## 8. Practice + interview questions

### Practice
- **PortSwigger Academy → OAuth authentication** — all labs (they cover `redirect_uri` theft, missing `state`, and flawed linking).
- Draw the Authorization Code + PKCE flow from memory and label what each param defends against. Do it until it's automatic.
- Set up a demo OAuth client (e.g., with Auth0/Keycloak) and break your own `redirect_uri` validation.

### Interview questions
- *Difference between OAuth and OIDC?* (Authorization vs authentication; access token vs ID token. The distinction underpins the confused-deputy bug.)
- *What does `state` defend against, precisely?* (CSRF on the flow — forced login / account linking.)
- *What is PKCE and what attack does it stop?* (Authorization-code interception; the `code` is useless without the `code_verifier`. Originally for public clients; now recommended everywhere.)
- *Why is Authorization Code safer than Implicit?* (Code is single-use and exchanged server-side; the token never appears in the URL/history.)
- *An app identifies users by reading the OAuth access token's `sub`. What's wrong?* (Access tokens aren't identity proof; a token issued to another client can impersonate — confused deputy. Use the ID token and validate `aud`/`iss`.)
- *Walk me through stealing an account via `redirect_uri`.* (Loose match / open-redirect on callback host → deliver `code` to attacker → exchange → ATO.)
- *What must a client validate on an ID token?* (Signature via JWKS, `iss`, `aud` = own client_id, `exp`, `nonce`.)
- *What's a pre-account-takeover in social login?* (Auto-linking OAuth identity to an unverified existing email; attacker pre-plants the email and inherits the victim's later login.)

---

**Related:** [[JWT-Attacks]] · [[Authentication-vs-Authorization]] · [[Session-Management]] · [[Open-Redirect]] · [[Chaining-Vulnerabilities]]
