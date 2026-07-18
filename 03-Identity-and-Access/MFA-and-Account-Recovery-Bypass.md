---
tags: [identity, mfa, a07]
owasp: A07:2025
status: learning
---

# MFA & Account Recovery Bypass

> MFA and password reset are the two flows that *intentionally* alter authentication, so they're where auth bugs concentrate. A strong MFA that's bypassable on step 2 is no MFA.

## MFA bypass patterns
| Bug | Mechanism |
|---|---|
| **Second factor not enforced server-side** | Skip the OTP step by going straight to the post-MFA endpoint; the "logged in" state was set after step 1 |
| **No rate limit on OTP** | Brute-force a 6-digit code (10^6, often crackable) — combine with [[Race-Conditions]] to beat counters |
| **OTP reuse / no expiry** | Replay an old code |
| **Response manipulation** | `{"mfa":"failed"}` → change to `success` on a client-trusting flow |
| **Backup/recovery code weakness** | Predictable or unlimited-attempt backup codes |
| **Fallback downgrade** | "Can't use authenticator? Use SMS/email" → attack the weaker channel |
| **MFA not required on password change / API tokens** | Change password or mint an API key to sidestep MFA entirely |
| **Remember-this-device forgeable** | Predictable trusted-device cookie |

**Core principle:** MFA state must be bound to a **server-side pending-authentication record**, and the session is only fully authenticated after the factor is verified server-side — never based on a client-supplied flag or reachable by skipping the step.

## Password reset (recap from [[Authentication-vs-Authorization]])
Test every reset flow for: token entropy/CSPRNG, single-use, expiry, tied to the account server-side (not `?user=` swappable), not leaked via `Referer`/response body, not built from the `Host` header (host header poisoning), and **all sessions invalidated after reset**.

## The fix
- Enforce the second factor server-side, bound to the pending-auth state; don't set full session until verified.
- Rate limit + lock OTP attempts; short expiry; single-use.
- Require re-auth/MFA for sensitive changes (password, email, MFA settings, API keys).
- Strong, limited, single-use recovery codes.
- Don't trust client-side success flags.

## Practice + interview
- PortSwigger Academy → authentication labs (2FA bypass, brute-force, reset).
- **Interview:** *Common MFA bypasses?* (Step not enforced server-side; OTP brute-force/no rate limit; response tampering; weaker-channel fallback; MFA not required on password change.) *How should MFA be enforced?* (Server-side, bound to pending-auth state, full session only after verification.)

---
**Related:** [[Authentication-vs-Authorization]] · [[Session-Management]] · [[Race-Conditions]]
