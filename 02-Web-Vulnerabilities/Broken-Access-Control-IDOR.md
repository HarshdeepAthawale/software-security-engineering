---
tags: [vuln, web, a01, access-control]
owasp: A01:2025
difficulty: easy-to-find, high-impact
status: learning
---

# Broken Access Control & IDOR

> **A01:2025 — the #1 risk.** In 2025 OWASP also folded **SSRF** into this category, because both are fundamentally "the server did something on behalf of a request it shouldn't have trusted." This is the vulnerability class you will find most often in the real world, and the one scanners are worst at finding — because they don't know your business rules.

---

## 1. What it actually is

The application fails to enforce **what an authenticated user is allowed to do or see**. The user is who they say they are (authN is fine); the app just doesn't properly restrict them (authZ is broken).

**IDOR** (Insecure Direct Object Reference) is the most common sub-type: the app exposes a reference to an internal object (a DB id, a filename, a key) and uses it to fetch data *without checking the requester owns it*.

```
GET /api/invoices/1043   → your invoice   ✅
GET /api/invoices/1044   → someone else's invoice   ❌ (no ownership check)
```

---

## 2. Root cause

The developer wrote the *retrieval* logic and forgot (or misplaced) the *authorization* logic. The object reference is trusted because it "came from our own frontend" — but the client controls every byte of the request. See [[Authentication-vs-Authorization]] for why this is structurally hard to avoid.

Three flavours of root cause:
1. **Missing check** — no authz code at all on the endpoint.
2. **Wrong check** — checks authentication ("are you logged in?") but not authorization ("is this yours?").
3. **Bypassable check** — the check exists but runs on a value the attacker controls, or only on one HTTP method, or only in the UI.

---

## 3. Vulnerable code

```python
# Flask — classic IDOR: authenticated, but no ownership check
@app.route('/api/invoices/<int:invoice_id>')
@login_required                          # ← authN only!
def get_invoice(invoice_id):
    inv = Invoice.query.get(invoice_id)  # fetches ANY invoice by id
    return jsonify(inv.to_dict())
```

```javascript
// Express — mass assignment (vertical escalation)
app.patch('/api/users/me', requireAuth, async (req, res) => {
  // req.body = {"name":"x", "role":"admin"}  ← role should not be settable
  const user = await User.findByIdAndUpdate(req.user.id, req.body);
  res.json(user);
});
```

```java
// Spring — vertical: no method-level authz, UI just hid the button
@PostMapping("/admin/promote")
public User promote(@RequestParam Long userId) {   // no @PreAuthorize
    return userService.makeAdmin(userId);
}
```

---

## 4. How to find it

### Black-box (the core methodology)
1. **Create two accounts**, A and B (attacker and victim).
2. **Map every endpoint** A touches. Note every object identifier: path segments, query params, JSON body fields, headers, cookies.
3. **Replay with substitution.** For each request, swap A's object IDs for B's, keeping A's session. Anything that returns B's data = IDOR.
4. **Don't stop at GET.** Test PUT/PATCH/DELETE — devs protect reads and forget writes.
5. **Test every ID location**, not just the obvious one: `?id=`, nested JSON (`{"user":{"id":X}}`), arrays (`ids[]=1&ids[]=2`), duplicated params, the `Referer`, custom headers like `X-Account-Id`.
6. **Manipulate identity, not just the object:** remove the auth header entirely (some endpoints fail open), downgrade role fields, try the request as an unauthenticated user.

### Techniques that find the non-obvious ones
| Technique | Finds |
|---|---|
| Change `Content-Type` and re-send | Endpoints with different authz per parser |
| Wrap ID in an array | Filters that check the scalar but query the array |
| Add a second ID param | Last-wins / first-wins parameter pollution |
| Swap sequential → UUID and back | Endpoints that accept *either* reference |
| Method override header | Bypassing method-scoped middleware |
| Path case/encoding (`/Admin`, `/%61dmin`, `/admin/`) | Route-based authz that's case/normalisation sensitive |

### Grey/white-box (code review)
Grep for data fetches that lack a tenant/owner filter:
```bash
# Django/SQLAlchemy: .get( or filter by pk with no user scoping nearby
grep -rn "objects.get(" .
grep -rn "\.query\.get(" .
grep -rn "findById\|findByPk\|findOne({ *_id" .
```
For each hit, ask: **is the current user's identity part of this query, or checked immediately after?** If neither, flag it.

---

## 5. Exploitation & escalation

IDOR is rarely the *end* of a chain — it's the multiplier. See [[Chaining-Vulnerabilities]].

- **Read** other users' PII → mass data exfiltration by iterating IDs (sequential IDs = automatable with Burp Intruder / a 10-line script).
- **Write** IDOR → change another user's email → trigger password reset → **full account takeover**.
- **Mass assignment** → set your own `role:admin` or `is_verified:true` or `balance:99999`.
- **Function-level** → hit `/admin/*` directly for privilege escalation.
- **BOLA in APIs** — the API equivalent (Broken Object Level Authorization) is API Top 10 #1; see [[API-Security-OWASP-API-Top-10]].

```python
# Exfil PoC — the entire attack is often this simple
import requests
s = {"Cookie": "session=YOUR_OWN_SESSION"}
for i in range(1000, 2000):
    r = requests.get(f"https://target/api/invoices/{i}", headers=s)
    if r.status_code == 200:
        print(i, r.json().get("customer_email"))
```

---

## 6. The fix

**Fix the class, not the instance.** Patching one endpoint leaves the other 399.

1. **Deny by default.** Every route requires an explicit authorization decision; a route with no policy fails a CI test.
2. **Scope queries to the principal** (fetch *and* authorize in one query — the pattern in [[Authentication-vs-Authorization]]):
   ```python
   inv = Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first()
   if inv is None:
       abort(404)
   ```
3. **Use unpredictable references** (UUIDv4) as defence-in-depth — but *never* as the primary control. "Unguessable" is not "authorized."
4. **Allowlist bindable fields** to kill mass assignment:
   ```python
   ALLOWED = {"name", "bio", "avatar"}
   updates = {k: v for k, v in req.body.items() if k in ALLOWED}
   ```
5. **Centralise** with a policy engine (OPA/Cedar) or a ReBAC service (OpenFGA/SpiceDB) for anything with sharing semantics.
6. **Enforce at the data layer** (row-level security in Postgres, tenant-scoped ORM managers) so it's structurally impossible to forget.

---

## 7. Real-world cases

- **Facebook (2015, "delete any photo album")** — a GraphQL mutation accepted an album `id` with no ownership check. Textbook IDOR, ~$12.5k.
- **USPS "Informed Visibility" (2018)** — an API let any authenticated user query account details for 60M users by changing parameters. Pure BOLA.
- **Peloton (2021)** — API returned private user data (age, gender, weight, workout stats) for any user ID, even with requests set to private.
- **Optus breach (2022)** — an unauthenticated API endpoint with enumerable identifiers exposed ~9.8M customers' data. Access control failure at national scale.
- **Parler (2021)** — sequential post IDs + no rate limiting → archivists scraped the entire site.

Study disclosed HackerOne reports tagged `IDOR` / `Broken Access Control` — hundreds exist and they're the fastest way to build pattern recognition.

---

## 8. Practice + interview questions

### Practice
1. **PortSwigger Web Security Academy → Access Control** — every lab. Free, and the definitive practice set.
2. Build the vulnerable Flask endpoint above, exploit it, then apply each fix and re-test.
3. On a lab app (Juice Shop), find 3 distinct IDORs and write each up in [[Report-Template]] format.
4. Write the 10-line exfil script and run it against your own lab. Feel how fast sequential IDs fall.

### Interview questions
- *What's the difference between authentication and authorization, and which causes more bugs?* → [[Authentication-vs-Authorization]]
- *How would you find IDORs in an app with 500 endpoints, efficiently?* (Two accounts, automate the replay-with-substitution, diff responses. Then argue for a *structural* fix so you're not playing whack-a-mole.)
- *A dev switched all IDs to UUIDs to "fix IDOR." Are they done?* (No. That's obscurity. If an attacker obtains a UUID — logs, referer, a share link, a second endpoint that leaks it — access is still granted. The authorization check is still missing.)
- *How do you prevent IDOR across an entire codebase, not one endpoint?* (Deny-by-default routing with mandatory policies, principal-scoped data layer / row-level security, CI test asserting every route declares authz, centralised authz service for sharing.)
- *Why did OWASP merge SSRF into Broken Access Control for 2025?* (Both are the server acting on an untrusted reference it failed to authorize — SSRF is the server fetching a URL it shouldn't; IDOR is the server fetching an object it shouldn't.)

---

**Related:** [[SSRF-Server-Side-Request-Forgery]] (now same category) · [[API-Security-OWASP-API-Top-10]] · [[Chaining-Vulnerabilities]] · [[Business-Logic-Flaws]]
