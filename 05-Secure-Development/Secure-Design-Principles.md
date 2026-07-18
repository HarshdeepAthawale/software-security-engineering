---
tags: [secure-dev, a06]
owasp: A06:2025
status: learning
---

# Secure Design Principles

> The timeless principles (Saltzer & Schroeder, 1975, still correct) that prevent whole classes of bugs by design. **A06:2025 — Insecure Design** exists because you can't patch your way out of a bad architecture.

## The principles that matter most
| Principle | Meaning | In practice |
|---|---|---|
| **Least privilege** | Every component gets the minimum access it needs | Scoped IAM, DB users without DDL, narrow OAuth scopes |
| **Fail securely / fail closed** | On error, deny — don't default to allow | `if not authorized: deny` even on exceptions; A10:2025 is about this |
| **Defense in depth** | Layered controls; no single point of failure | WAF + parameterized queries + least-priv DB |
| **Complete mediation** | Check *every* access, every time | Authorize each request/object — the [[Broken-Access-Control-IDOR]] lesson |
| **Secure defaults** | Safe out of the box; opt *out* of security, never *in* | MFA on by default, private by default |
| **Economy of mechanism** | Keep it simple — complexity hides bugs | Simple authz beats a clever one nobody understands |
| **Separation of duties** | No single actor completes a sensitive action alone | Approval workflows for payouts |
| **Least common mechanism** | Don't share state/resources across trust levels | Tenant isolation |
| **Open design** | Security must not depend on secrecy of the design | Kerckhoffs — the key is secret, not the algorithm ([[Cryptography-Fundamentals]]) |
| **Psychological acceptability** | If security is painful, users route around it | Usable MFA, sensible password rules |
| **Zero trust** | Never trust based on network location | Authenticate/authorize every call, incl. internal |

## Applying them
- **Trust boundaries** are where these principles get enforced — identify them via [[Threat-Modeling]].
- **"Secure by default" is the highest-leverage one for a product**: if the safe path is the default and the easy one, most bugs never happen.
- **Fail closed** deserves special attention in 2026 — A10:2025 (Mishandling of Exceptional Conditions) is new precisely because error paths that fail *open* (an exception skips the authz check, a timeout returns cached admin data) are a recurring root cause.

## Interview
- *Name secure design principles and apply one to a real feature.* (Pick least privilege or fail-closed and give a concrete example.) *Difference between a design flaw and an implementation bug?* (Design flaws are architectural — no amount of patching fixes them; you must redesign. That's why threat modeling at design time matters.) *What does "fail securely" mean?* (On any error/exception, deny access rather than default-allow.)

---
**Related:** [[Threat-Modeling]] · [[Authentication-vs-Authorization]] · [[Secrets-Management]]
