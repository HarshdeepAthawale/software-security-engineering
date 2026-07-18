---
tags: [modern, api]
status: learning
---

# API Security (OWASP API Top 10)

> APIs get their **own** OWASP Top 10 because they fail differently from server-rendered web pages: there's no UI to hide behind, every object is directly addressable, and **authorization** is the dominant failure mode. If you know web vulns, this is mostly "the same bugs, but authorization is even more central and the attack surface is more machine-readable."

---

## 1. The API Top 10 (2023 edition — current)

| # | Risk | Essence | Deep note |
|---|---|---|---|
| **API1** | **BOLA** — Broken Object Level Authorization | The #1 API bug = IDOR. `/orders/{id}` returns any order, no ownership check | [[Broken-Access-Control-IDOR]] |
| API2 | Broken Authentication | Weak/again-usable tokens, no expiry, credential stuffing, weak reset | [[Authentication-vs-Authorization]] |
| **API3** | **BOPLA** — Broken Object *Property* Level Auth | Mass assignment (writes) + excessive data exposure (reads) | §3 below |
| API4 | Unrestricted Resource Consumption | No rate limit/quota → DoS, cost, brute force | §4 |
| **API5** | **BFLA** — Broken Function Level Authorization | Low-priv user calls admin/other-role endpoints directly | [[Authentication-vs-Authorization]] |
| API6 | Unrestricted Access to Business Flows | Automating a flow that shouldn't be automated (bulk-buy, spam, scalping) | [[Business-Logic-Flaws]] |
| API7 | SSRF | A URL/reference param fetched server-side | [[SSRF-Server-Side-Request-Forgery]] |
| API8 | Security Misconfiguration | CORS, verbose errors, missing hardening, unpatched | — |
| API9 | Improper Inventory Management | Shadow/zombie APIs — old `/v1`, `/beta`, `/internal` still live & unpatched | §5 |
| API10 | Unsafe Consumption of 3rd-Party APIs | Blindly trusting data from an upstream API | — |

**Three of the top five (API1, API3, API5) are authorization failures.** APIs live or die on object-, property-, and function-level authorization. This is why [[Broken-Access-Control-IDOR]] and [[Authentication-vs-Authorization]] are your most important notes.

---

## 2. API1 — BOLA (the #1 bug), in detail
Identical mechanism to IDOR: an object reference in the request, no server-side check that the caller owns it.

```http
GET /api/v2/orders/1044        Authorization: Bearer <your-token>
→ 200 {"id":1044,"customer":"someone-else","total":900,"address":"..."}
```

**Test methodology (from [[Broken-Access-Control-IDOR]]):** two accounts A and B, capture every request A makes, replay each with B's token and A's object IDs. Every request returning A's data = BOLA. Don't stop at GET — test PUT/PATCH/DELETE, nested IDs (`{"user":{"id":X}}`), arrays (`ids[]=`), and secondary identifiers (`?invoice_no=1002` even when the primary `id` is a UUID).

---

## 3. API3 — BOPLA (property-level): two faces

### 3a. Excessive Data Exposure (reads)
The API returns the *entire* object; the **frontend hides** the sensitive fields, but the raw JSON contains them.
```javascript
// ❌ returns the whole model
app.get('/api/users/:id', (req, res) => res.json(user));
// raw response leaks: password_hash, is_admin, internal_notes, ssn, reset_token...
```
Client-side hiding is **not a control**. Always read the raw response, never the rendered UI.
```javascript
// ✅ explicit output schema / serializer — whitelist fields
res.json({ id: user.id, name: user.name, avatar: user.avatar });
```

### 3b. Mass Assignment (writes)
The API binds *all* incoming JSON fields to the model, so the client sets fields it shouldn't.
```http
PATCH /api/users/me
{"name":"Bob","role":"admin","email_verified":true,"balance":99999}
```
```python
# ❌ binds everything
user.update(**request.json)
# ✅ allowlist bindable fields
ALLOWED = {"name", "bio", "avatar"}
user.update(**{k: v for k, v in request.json.items() if k in ALLOWED})
```
Find target fields by reading GET responses (they reveal the model's field names) — then try writing them back.

---

## 4. API4 — Unrestricted Resource Consumption
No rate limits / quotas enables: OTP & password-reset **brute force**, user/data **enumeration**, scraping, and cost/DoS (expensive queries, large `page_size`, GraphQL batching → [[GraphQL-Security]]). Test: send bursts, tamper `limit`/`page_size`, remove pagination. Fix: per-user *and* per-IP limits, quotas, max page size, timeouts, cost analysis.

---

## 5. API9 — Shadow / Zombie APIs
Old versions and undocumented endpoints that never got the fixes the current version received.
- Enumerate versions: `/api/v1`, `/v2`, `/internal`, `/beta`, `/legacy`, `/mobile`.
- Pull the spec if exposed: `/openapi.json`, `/swagger.json`, `/api-docs`, `/.well-known/`.
- Extract endpoints from frontend JS bundles (your `web2-recon` skill: LinkFinder, katana).
- Documented ≠ complete — fuzz for hidden routes.
An `/api/v1/users/{id}` that still works and predates the authz fix in v2 is a classic finding.

---

## 6. Discovery workflow (API pentest recon)
1. Proxy the mobile/web app through Burp/Caido → capture the real API traffic.
2. Grab any OpenAPI/Swagger/GraphQL introspection → full surface map.
3. Mine JS bundles for endpoints, keys, and undocumented routes.
4. Enumerate versions and guess sibling endpoints from naming patterns.
5. For each endpoint: check authN, then object/function/property authZ, then rate limiting, then injection in parameters.

## 7. The fix (summary)
- **Authorize every object, function, and property server-side, per request** — scope queries to the principal (structural pattern in [[Authentication-vs-Authorization]]).
- **Explicit response schemas / serializers** — return only whitelisted fields; never dump the whole model.
- **Allowlist bindable input fields** (kills mass assignment).
- **Rate limits + quotas + max page size** on every endpoint, especially auth/OTP/reset.
- **API inventory + version lifecycle** — decommission old versions; scan for shadow APIs.
- An **API gateway** can do authN, schema validation, and rate limiting — but **object-level authz still belongs in the app** (the gateway doesn't know who owns object 1044).

## 8. Real-world cases
- **USPS Informed Visibility (2018)** — an API let any authenticated user query account data for ~60M users by changing parameters. Pure BOLA at scale.
- **Peloton (2021)** — API returned private profile data (age, weight, workout stats) for any user ID, even when set to private. BOLA + excessive data exposure.
- **T-Mobile / various telco breaches** — unauthenticated or under-authorized APIs with enumerable IDs.
- **Experian, Coinbase, Uber** — many disclosed BOLA/BFLA and mass-assignment API reports; high bounties.

## 9. Practice + interview questions

### Practice
- **PortSwigger Academy → API testing** labs; **OWASP crAPI** (deliberately vulnerable API); Juice Shop's API challenges.
- Proxy a real app, extract its API from JS, and run the two-account BOLA methodology.

### Interview questions
- *What's BOLA and why is it #1 for APIs?* (Object-level authz missing; no UI to hide behind; every object directly addressable and enumerable.)
- *Excessive data exposure — but the frontend hides those fields?* (Client-side hiding isn't a control; the raw API response leaks them. Fix with server-side output schemas.)
- *What's mass assignment and how do you prevent it?* (Binding all input fields to the model; allowlist bindable fields.)
- *How do you find shadow APIs and why do they matter?* (Old versions/undocumented routes via version enumeration, swagger, JS mining, fuzzing; they lag on security fixes.)
- *An API gateway does authN and rate limiting — are we covered for authz?* (No — object-level authz needs app context the gateway lacks; it can't know ownership.)
- *Why is rate limiting an API-specific concern?* (Brute force of OTP/reset, enumeration, scraping, cost/DoS — machine clients hit endpoints fast.)

---

**Related:** [[Broken-Access-Control-IDOR]] · [[Authentication-vs-Authorization]] · [[GraphQL-Security]] · [[SSRF-Server-Side-Request-Forgery]] · [[Business-Logic-Flaws]]
