---
tags: [identity, session, a07]
owasp: A07:2025
status: learning
---

# Session Management

> After you authenticate, *something* remembers you're logged in across stateless HTTP requests. That something is the session, and how it's stored, transmitted, and destroyed is a rich bug surface.

## Session token: cookie vs token storage
| Approach | Pros | Cons / risks |
|---|---|---|
| **Opaque session ID in HttpOnly cookie** (server-side session) | Revocable instantly; not readable by JS; auto-sent | CSRF surface (mitigate: SameSite + tokens) |
| **JWT in cookie** | Stateless | Can't easily revoke; see [[JWT-Attacks]] |
| **JWT/token in `localStorage`** | Easy for SPAs | **XSS reads it directly; no HttpOnly** — generally the weakest for sessions |

**Recommendation for most apps:** opaque session ID in a `HttpOnly; Secure; SameSite=Lax` cookie with the `__Host-` prefix, server-side session store, instant revocation. The stateless-JWT-session trend trades away revocation and invites [[JWT-Attacks]].

## Cookie hardening (recap from [[Browser-Security-Model]])
```
Set-Cookie: __Host-session=<opaque>; HttpOnly; Secure; SameSite=Lax; Path=/
```
`__Host-` forces Secure + no Domain + Path=/ — the strongest available.

## The bugs
| Bug | Attack | Fix |
|---|---|---|
| **Session fixation** | Attacker sets victim's session ID *before* login, then hijacks after | **Regenerate the session ID on every privilege change** (login, step-up) |
| Predictable session ID | Guess/brute-force | CSPRNG, ≥128-bit → [[Cryptography-Fundamentals]] |
| No expiry | Stolen token valid forever | Absolute + idle timeouts |
| No server-side revocation | Can't force logout / kill stolen tokens | Server-side session store or a token denylist |
| Token in URL | Leaks via history/Referer/logs | Never put session tokens in URLs |
| Not invalidated on logout/password-reset | Old session stays alive | Destroy server-side on logout and on credential change; invalidate *all* sessions on password reset |
| Cookie scoped to parent domain | Subdomain XSS/takeover steals it | Scope narrowly; `__Host-` (no Domain) |
| Concurrent-session sprawl | Stolen token undetected | Session list + "log out other devices" |

## Logout must actually destroy state
A logout that just deletes the client cookie but leaves the server session valid is a real finding — a stolen/leaked token still works. Destroy it server-side.

## Practice + interview
- PortSwigger Academy → authentication/session labs; test session fixation and logout-invalidation on a lab app.
- **Interview:** *Cookie vs localStorage for tokens?* (HttpOnly cookie protects against XSS theft + is revocable; localStorage is XSS-exposed. Cookie needs CSRF defence.) *What's session fixation and the fix?* (Attacker pre-plants a session ID; regenerate ID at login.) *How do you revoke a JWT-based session?* (You can't cleanly — need denylist/short-expiry; a reason to prefer server-side sessions.) *What should happen to sessions on password reset?* (Invalidate all of them.)

---
**Related:** [[Authentication-vs-Authorization]] · [[JWT-Attacks]] · [[CSRF-Cross-Site-Request-Forgery]] · [[Browser-Security-Model]]
