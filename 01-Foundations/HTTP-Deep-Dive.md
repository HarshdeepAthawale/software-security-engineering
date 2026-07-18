---
tags: [foundations, http]
status: learning
---

# HTTP Deep Dive

> If you don't understand HTTP at the byte level, every web vulnerability will feel like magic. It isn't. It's all text parsing and trust.

---

## The raw request

```http
POST /api/v2/transfer HTTP/1.1
Host: bank.example.com
User-Agent: Mozilla/5.0
Content-Type: application/json
Content-Length: 47
Cookie: session=eyJhbGciOi...; theme=dark
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Origin: https://bank.example.com

{"to_account":"12345","amount":100,"currency":"USD"}
```

Four things to internalize:

1. **It's just text** with `\r\n` line endings, and a blank line separating headers from body. Every parser in the chain (CDN → load balancer → app server → framework) parses this text *slightly differently*. That gap is [[HTTP-Request-Smuggling]].
2. **The client controls everything.** Every header, the method, the path, the body. `User-Agent`, `Host`, `X-Forwarded-For` — all attacker-controlled. Any security decision based on them is broken by default.
3. **`Content-Length` and `Transfer-Encoding`** tell the server where the body ends. Disagreement between two servers about which to trust = request smuggling.
4. **Cookies are sent automatically** by the browser. That's the entire basis of [[CSRF-Cross-Site-Request-Forgery]].

---

## Methods, and why they matter for security

| Method | Safe? | Idempotent? | Security relevance |
|---|---|---|---|
| GET | yes | yes | Params land in logs, `Referer`, browser history → **never put secrets in a GET query string** |
| POST | no | no | The default for state change; CSRF-protectable |
| PUT / PATCH | no | PUT yes | Often forgotten in authz checks — devs protect POST and forget PUT |
| DELETE | no | yes | Same |
| OPTIONS | yes | yes | CORS preflight; leaks allowed methods |
| TRACE | yes | yes | Cross-Site Tracing (XST) — should be disabled |
| HEAD | yes | yes | Sometimes bypasses auth filters that only match GET/POST |

**Real bug pattern:** a framework routes `GET /admin` through an auth middleware matched on the literal method `GET`. `HEAD /admin` or a method-override header (`X-HTTP-Method-Override: GET`) skips the middleware. Always test verb tampering.

---

## Headers that matter for security

### Request headers you must never trust
| Header | Attacker-controlled | Common misuse |
|---|---|---|
| `Host` | ✅ | Password reset link built from `Host` → **host header poisoning** → account takeover |
| `X-Forwarded-For` | ✅ | Rate limiting / IP allowlisting by XFF → trivially spoofed |
| `Referer` | ✅ | CSRF defence via Referer → strippable |
| `User-Agent` | ✅ | Ends up in SQL/logs → injection sink |
| `Origin` | ⚠️ | Browser-set for CORS/CSRF; trustworthy *from a browser*, but not from curl |

> Rule: `Origin` is set by the browser and cannot be spoofed by JS, which is why it's usable for CSRF defence. Everything else in that list is free-form attacker input.

### Response headers you should be setting

| Header | Value | Protects against |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; base-uri 'none'` | [[XSS-Cross-Site-Scripting]] impact |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | SSL stripping / MITM |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing → stored XSS via uploads |
| `Content-Security-Policy: frame-ancestors` | `'none'` | Clickjacking (supersedes `X-Frame-Options`) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | URL/token leakage to third parties |
| `Cache-Control` | `no-store` on authenticated responses | [[Web-Cache-Poisoning]] and shared-cache leaks |
| `Permissions-Policy` | `camera=(), geolocation=()` | Feature abuse in embedded content |

Missing headers alone are usually **not** a valid bug bounty finding — see [[Vulnerability-Management-and-Triage]]. They matter as defence-in-depth, not as a vuln.

---

## Status codes as an information leak

Status codes are an oracle. Attackers read the difference, not the value.

```
POST /login  {"user":"admin","pass":"wrong"}   → 401 "Invalid password"
POST /login  {"user":"nobody","pass":"wrong"}  → 401 "User not found"
```
That difference is **username enumeration**. Same for:
- `403` vs `404` on an object ID → tells you the object exists → helps [[Broken-Access-Control-IDOR]]
- Timing differences even when the message is identical → see [[Race-Conditions]] for timing methodology

**Fix:** identical response, identical status, and constant-ish timing for both cases.

---

## HTTP/1.1 vs HTTP/2 vs HTTP/3

| | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---|---|---|---|
| Framing | Text, `\r\n` | Binary frames | Binary over QUIC/UDP |
| Multiplexing | No (pipelining broken) | Yes, streams | Yes, no head-of-line blocking |
| Header format | Plain text | HPACK compressed | QPACK |
| Security impact | Ambiguous body length → smuggling | Downgrade to h1 at the backend → **H2.CL / H2.TE smuggling** | Same class, plus UDP amplification concerns |

**The key modern insight:** most CDNs speak HTTP/2 to the client and downgrade to HTTP/1.1 to the origin. That translation step re-introduces length ambiguity. This is where most 2020s request smuggling lives. See [[HTTP-Request-Smuggling]].

---

## Content-Type: the underrated attack surface

The parser chosen by `Content-Type` decides which vulnerability class applies.

| Content-Type | Parser | Attack surface |
|---|---|---|
| `application/json` | JSON | Type confusion, mass assignment, prototype pollution |
| `application/xml` | XML | [[XXE-and-XML-Attacks]] |
| `application/x-www-form-urlencoded` | Form | Parameter pollution, array notation tricks |
| `multipart/form-data` | Multipart | [[Path-Traversal-and-File-Upload]], boundary parsing bugs |
| `application/yaml` | YAML | [[Insecure-Deserialization]] (`!!python/object`) |

**Technique:** switch the `Content-Type` and reformat the body. An endpoint that expects JSON but also accepts XML (because the framework is content-negotiating) is an instant XXE candidate. This one trick has paid out many bounties.

---

## Practice

1. Use `nc` or `openssl s_client` to hand-write a raw HTTP request to a site. No curl, no browser.
   ```bash
   printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' | openssl s_client -quiet -connect example.com:443
   ```
2. Capture a login flow in Burp. Annotate every single header — who set it, and can you control it?
3. Take an API endpoint that accepts JSON. Try: XML body, form-encoded body, array instead of string, `null`, deeply nested object. Note every different error.
4. Find one site where `403` and `404` differ for objects you don't own. That's an enumeration primitive.

---

## Interview questions

- *Walk me through everything that happens when I type a URL and hit enter.* (Classic. They're checking depth — DNS, TLS handshake, HTTP, rendering, and the security control at each step.)
- *Why can't JavaScript spoof the `Origin` header?* (Browser-controlled forbidden header; that's why CSRF defence can rely on it.)
- *A dev says they'll fix CSRF by checking `Referer`. What's your response?* (Referer can be absent — privacy settings, `Referrer-Policy: no-referrer`, HTTPS→HTTP. If your code treats "absent" as "allow", it's bypassed. If as "deny", you break real users.)
- *What's the difference between 401 and 403?* (401 = unauthenticated, challenge expected; 403 = authenticated but not permitted. Most APIs get this wrong, and the inconsistency leaks info.)

---

**Next:** [[Browser-Security-Model]]
