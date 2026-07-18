---
tags: [foundations, authn, authz]
owasp: A01:2025, A07:2025
status: learning
---

# Authentication vs Authorization

> **AuthN**: who are you? **AuthZ**: what are you allowed to do?
>
> Authentication is a solved problem you should buy, not build. Authorization is unsolved, custom to every app, and therefore where the bugs are. That's why **Broken Access Control is A01** and has been the #1 risk for years.

---

## Why authorization is so much harder

Authentication happens **once**, at one place — the login endpoint. You can review it, harden it, test it.

Authorization must happen **on every single request, for every single object, for every single field**. Miss one endpoint out of four hundred and you have a critical vulnerability. There is no central place to get it right unless you deliberately build one.

```
Authentication:  400 endpoints → 1 middleware → easy to verify
Authorization:   400 endpoints × N objects × M fields → 
                 every one is an independent chance to fail
```

This asymmetry is the entire reason [[Broken-Access-Control-IDOR]] dominates real-world findings.

---

## Authorization models

### 1. Role-Based Access Control (RBAC)
Users have roles; roles have permissions.
```
alice → role:editor → [post.create, post.edit, post.publish]
```
- ✅ Simple, auditable, easy to explain
- ❌ **Role explosion** — "editor but only for the marketing team in the EU region"
- ❌ Doesn't answer *which* post — RBAC says you can edit posts, not *this* post. **Most IDORs are RBAC-only apps missing an ownership check.**

### 2. Attribute-Based Access Control (ABAC)
Decisions from attributes of subject, object, action, environment.
```
allow if user.department == doc.department 
       and user.clearance >= doc.classification 
       and time.now in business_hours
```
- ✅ Expressive, handles ownership naturally
- ❌ Hard to reason about; "who can access X?" becomes an expensive query

### 3. Relationship-Based Access Control (ReBAC)
Permissions derived from a graph of relationships. Google's **Zanzibar** paper is the canonical design; open-source implementations: OpenFGA, SpiceDB, Ory Keto.
```
document:budget#viewer@group:finance#member
folder:reports#parent@document:budget     → viewer inherits down the tree
```
- ✅ Correct model for sharing/collaboration products (Drive, GitHub, Notion)
- ✅ Centralises authz into one auditable service — huge security win
- ❌ Operational complexity

> **Interview gold:** knowing Zanzibar/ReBAC exists puts you ahead of most candidates. It's the direction serious companies are moving.

### 4. Policy-as-code
OPA/Rego, Cedar (AWS). Policies live in version control, get tested in CI, and are enforced by a central engine.

---

## Where authorization checks belong

```
❌ In the frontend            — trivially bypassed; UI hiding is not a control
❌ In an API gateway alone    — knows the route, not the object
⚠️  In each controller        — works, but N chances to forget
✅ In the data access layer   — hardest to bypass, because every path goes through it
```

### The single most valuable pattern to know

Instead of *fetch then check*:
```python
# ❌ Fragile: the check is separate and forgettable
doc = db.query("SELECT * FROM documents WHERE id = ?", doc_id)
if doc.owner_id != current_user.id:
    abort(403)
return doc
```

Make ownership **part of the query** so a missing check yields no data, not wrong data:
```python
# ✅ Safe by construction: fails closed
doc = db.query(
    "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
    doc_id, current_user.id
)
if not doc:
    abort(404)   # 404 not 403 — don't leak object existence
return doc
```

Better still, scope at the ORM level so it's impossible to forget:
```python
# Every query is automatically tenant-scoped
class TenantQuerySet(models.QuerySet):
    def for_user(self, user):
        return self.filter(tenant_id=user.tenant_id)
```

**In code review, this is what you look for:** is authorization *structural* (impossible to forget) or *incidental* (a line someone remembered to write)?

---

## Authentication: the parts that break

Maps to **A07:2025 — Authentication Failures**.

| Weakness | Attack | Defence |
|---|---|---|
| Weak passwords allowed | Credential stuffing | Breached-password check (HIBP k-anonymity API), min 12 chars, no forced rotation |
| No rate limit on login | Brute force | Per-account **and** per-IP limits, exponential backoff, CAPTCHA after N |
| Username enumeration | Target valid accounts | Identical responses & timing for valid/invalid users |
| Predictable reset tokens | Account takeover | 128-bit CSPRNG, single-use, ~15 min expiry, invalidate on use |
| Reset token in `Referer` | Token leak to third parties | Token in POST body, `Referrer-Policy` |
| Session not rotated on login | **Session fixation** | Regenerate session ID at every privilege change |
| Sessions never expire | Stolen token valid forever | Absolute + idle timeouts, server-side revocation |
| MFA only checked on step 2 | [[MFA-and-Account-Recovery-Bypass]] | Bind the MFA step to a server-side pending-auth state |
| OAuth `state` missing | CSRF on login → account linking attack | See [[OAuth2-and-OIDC]] |

### The password reset flow — test it every time
It's the highest-value target in any app because it *intentionally* bypasses authentication.

1. Is the token random enough? (Capture 20, look for patterns/timestamps.)
2. Is it tied to the user account server-side, or is the user ID also a parameter? (`?token=X&user=victim` → mismatch check missing = ATO)
3. Does it expire? Is it single-use?
4. Is the reset link built from the `Host` header? → **host header poisoning** → send the victim a legitimate email whose link points at your server.
5. Are all sessions invalidated after reset?
6. Can you request a reset for another user and receive the token in the *response body*? (Happens more than you'd think.)

---

## Common authorization bug patterns (memorise these)

| Pattern | Example |
|---|---|
| **Horizontal** — same role, other user's data | `GET /api/orders/1002` when you own 1001 |
| **Vertical** — lower role reaching higher function | User hits `POST /admin/users` directly |
| **Missing function-level authz** | UI hides the admin button; endpoint is open |
| **Mass assignment** | `PATCH /users/me {"role":"admin"}` — the field wasn't in the form, but the model binds it |
| **Context-dependent** | Can cancel an order *after* it shipped |
| **Second-order** | You can't read `/docs/5`, but you can add it to a folder you own and read it there |
| **IDOR via a secondary key** | `id` is a UUID (good) but `?invoice_number=1002` is sequential (bad) |
| **Static resource** | `/reports/2026-payroll.pdf` served directly by nginx, no authz at all |

---

## Practice

1. Take any app with two user accounts. Enumerate every endpoint from account A's traffic, then replay each one with account B's session and A's object IDs. Log every one that returns data. (This is literally the job.)
2. Implement RBAC, then ABAC, then a tiny ReBAC check on a toy app. Feel where each breaks down.
3. Test a password reset flow against all 6 questions above.
4. Read the [Zanzibar paper](https://research.google/pubs/pub48190/) — at least sections 1–3.

---

## Interview questions

- *Difference between authentication and authorization?* (Warm-up. Give the one-liner, then immediately add *why authz is harder* — that's the answer they remember.)
- *Why is Broken Access Control the #1 OWASP risk?* (Per-request/per-object surface, no central choke point unless designed in, and scanners can't find it because they don't know your business rules.)
- *How would you design authorization for a Google-Docs-like sharing feature?* (ReBAC/Zanzibar; relationship tuples; inheritance through folders; centralised decision service; check at the data layer.)
- *You find an endpoint returning 403 for other users' objects but 404 for nonexistent ones. Is that a bug?* (Yes — object existence oracle. Minor alone; useful for enumeration in a chain.)
- *How do you prevent an entire class of IDORs, not just one?* (Structural: tenant-scoped query layer, mandatory authz decorators with a deny-by-default router test, plus a CI check that every route declares a policy.)

---

**Related:** [[Broken-Access-Control-IDOR]] · [[Session-Management]] · [[OAuth2-and-OIDC]]
