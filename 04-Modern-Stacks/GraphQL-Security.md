---
tags: [modern, graphql, api]
status: learning
---

# GraphQL Security

> GraphQL hands query power to the client — great for developers, great for attackers. The underlying bugs are the same as REST ([[Broken-Access-Control-IDOR]], injection, [[Business-Logic-Flaws]]) plus GraphQL-specific issues arising from introspection, a single endpoint, aliasing/batching, and deeply nested queries.

---

## 1. How GraphQL differs (and why that creates bugs)
- **One endpoint** (`/graphql`) for everything — so per-*route* authz is meaningless; authorization must be per-**field** and per-**object** in resolvers.
- **The client chooses fields** — so "excessive data exposure" is one extra field away.
- **Introspection** — the schema can describe itself, handing attackers a full map (including hidden/admin mutations).
- **Aliasing & batching** — many logical operations in one HTTP request → rate limits keyed per-request are trivially bypassed.
- **Nested/recursive queries** — a cheap request can trigger enormous server work → DoS.

---

## 2. Recon — always start here
```graphql
# Full introspection — the schema, every type, field, arg, and mutation
query { __schema { types { name fields { name args { name type { name } } } }
                   queryType { name } mutationType { name } } }
# Quick type probe
query { __type(name:"User") { name fields { name type { name } } } }
```
- Endpoints to try: `/graphql`, `/graphql/console`, `/graphiql`, `/v1/graphql`, `/api/graphql`, `/query`.
- **Introspection disabled?** Recover the schema via **field suggestions** ("Did you mean `email`?") — tools **clairvoyance** / **graphql-cop** brute-force the schema from error hints.
- Tooling: **InQL** (Burp extension), **GraphQL Voyager** (visualise the schema), **graphql-cop**, **graphw00f** (engine fingerprint).

---

## 3. The bug catalogue

| Issue | Mechanism | Test |
|---|---|---|
| **Introspection exposed** | `__schema` enabled in prod | Dump full schema → find hidden mutations (`deleteUser`, `makeAdmin`) |
| **Broken object/field authz** | Authz assumed at endpoint, not resolver | Query another user's object by id; request admin-only fields as a normal user |
| **Excessive data exposure** | Sensitive fields queryable | Ask for `passwordHash`, `resetToken`, `isAdmin`, `internalNotes` on a type |
| **Batching/alias brute-force** | Many operations per request bypass rate limits | See §4 |
| **Query depth/complexity DoS** | Recursive nesting | See §5 |
| **Injection in resolvers** | Args flow into SQL/NoSQL/OS in the resolver body | Same sinks as [[Injection-SQLi]] — the resolver is where it lands |
| **Mutation mass assignment** | Input types accept fields they shouldn't | Set `role`/`isAdmin`/`verified` via a mutation input object |
| **IDOR via mutations** | `updateUser(id: 999, ...)` no ownership check | [[Broken-Access-Control-IDOR]] |
| **Verbose errors** | Stack traces / DB errors in `errors[]` | Leak internals, aid injection |
| **CSRF on GraphQL** | Accepts `application/x-www-form-urlencoded` or GET | State-changing mutation via [[CSRF-Cross-Site-Request-Forgery]] |

---

## 4. Batching & aliasing — the signature GraphQL attack
One HTTP request can carry many operations, defeating per-request rate limiting (e.g. brute-forcing OTP/login):

```graphql
# Alias-based: 100 login attempts in ONE request
mutation {
  a: login(user:"admin", pass:"password1") { token }
  b: login(user:"admin", pass:"password2") { token }
  c: login(user:"admin", pass:"password3") { token }
  # ... up to hundreds
}
```
Or **array batching** — send `[{query...},{query...},...]` as a JSON array. Both turn "5 attempts/min" into "500 attempts/request." Test both; this is a very common real finding.

## 5. Depth / complexity DoS
```graphql
query {
  posts { author { posts { author { posts { author { posts {
    author { name } } } } } } } }   # recursive relationship → exponential resolution
}
```
A tiny request forces massive server work. Also: requesting huge lists without pagination, or many aliased expensive fields.

## 6. The fix
- **Authorize in resolvers, at the field/object level** — never assume "authenticated at the endpoint" = authorized. Centralise with directives (`@auth`) or a policy layer so it's not per-resolver-remembered → see [[Authentication-vs-Authorization]].
- **Disable introspection in production** (defence-in-depth, not an access control — assume the schema is known anyway).
- **Query cost analysis + depth limiting + timeouts** (graphql-depth-limit, cost-analysis plugins); paginate all lists.
- **Rate-limit per *operation*, and cap batch/alias counts** — not per HTTP request. Disable array batching if unused.
- **Parameterize** resolver DB/OS calls; **allowlist** mutation input fields (kill mass assignment).
- **Generic errors** in production; strip stack traces.
- **Persisted (allowlisted) queries** for high-security APIs — only known query hashes are accepted, eliminating arbitrary queries entirely.
- Enforce a non-`GET`, JSON-only content type to reduce CSRF surface.

## 7. Real-world cases
- **HackerOne, GitLab, Shopify, GitHub** — all run GraphQL and have disclosed reports: introspection-exposed hidden mutations, missing resolver authz (IDOR), and batching-based brute force. GitLab's GraphQL has produced several public authz findings.
- **Facebook** (GraphQL's origin) — early disclosed object-authz mutations (e.g. album deletion) are the archetype.
- Batching-based **2FA/OTP brute force** appears repeatedly in bounty writeups.

## 8. Practice + interview questions

### Practice
- **PortSwigger Academy → GraphQL API vulnerabilities** — all labs (introspection, suggestions when introspection is off, IDOR via GraphQL, bypassing rate limits with aliases).
- Stand up a vulnerable GraphQL server (e.g. **DVGA — Damn Vulnerable GraphQL Application**) and run InQL + the alias brute-force.

### Interview questions
- *Why is authorization different in GraphQL vs REST?* (Single endpoint → per-field/object authz in resolvers, not per-route.)
- *Why is rate limiting harder in GraphQL?* (Aliasing/batching packs many operations into one HTTP request; limit per operation and cap batch size.)
- *First thing you check on a GraphQL endpoint?* (Introspection → full schema and hidden mutations; if off, use field suggestions/clairvoyance.)
- *How can GraphQL cause DoS?* (Deeply nested/recursive queries and unpaginated lists → exponential resolver work; fix with depth/cost limits + timeouts.)
- *Is injection possible in GraphQL?* (Yes — the resolver passes args to SQL/NoSQL/OS; GraphQL doesn't sanitize. Parameterize as usual.)

---

**Related:** [[API-Security-OWASP-API-Top-10]] · [[Broken-Access-Control-IDOR]] · [[Injection-SQLi]] · [[Business-Logic-Flaws]] · [[CSRF-Cross-Site-Request-Forgery]]
