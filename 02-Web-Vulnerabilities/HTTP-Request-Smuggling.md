---
tags: [vuln, web, smuggling]
difficulty: very-high
status: learning
---

# HTTP Request Smuggling

> Two servers in a chain — a front-end (CDN / reverse proxy / load balancer) and a back-end origin — **disagree about where one HTTP request ends and the next begins.** The attacker exploits that disagreement to smuggle a partial request that gets prepended to the *next* user's request. High skill ceiling, high impact: capture other users' requests, bypass front-end controls, and poison caches. Builds directly on the length-ambiguity theme in [[HTTP-Deep-Dive]].

---

## 1. Root cause — two ways to say "where the body ends"

HTTP/1.1 offers two mechanisms to delimit a message body:
- **`Content-Length: N`** — the body is exactly N bytes.
- **`Transfer-Encoding: chunked`** — the body is a series of hex-sized chunks, terminated by a `0\r\n\r\n` chunk.

If a request contains **both**, the RFC says `Transfer-Encoding` wins. But real servers don't always agree — and when the **front-end** uses one to determine length while the **back-end** uses the other, part of the attacker's body is re-interpreted by the back-end as the **start of the next request** on that reused connection.

Prerequisite: the front-end and back-end **reuse the TCP connection** for multiple requests (near-universal for performance).

---

## 2. The classic variants

| Variant | Front-end uses | Back-end uses | Trick |
|---|---|---|---|
| **CL.TE** | Content-Length | Transfer-Encoding | FE thinks body is short; BE processes chunked, sees leftover as next request |
| **TE.CL** | Transfer-Encoding | Content-Length | Reverse |
| **TE.TE** | both, but one is **obfuscated** so a server ignores it | e.g. `Transfer-Encoding: xchunked`, ` Transfer-Encoding: chunked`, `Transfer-Encoding:\tchunked`, double header |
| **H2.CL / H2.TE** | HTTP/2 (frontend) downgraded to HTTP/1.1 (backend) | length ambiguity reintroduced at the downgrade | **the modern frontier** |

### CL.TE example
```http
POST / HTTP/1.1
Host: victim.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
- **Front-end (CL=13):** forwards the whole thing as one request body of 13 bytes.
- **Back-end (TE):** reads the `0\r\n\r\n` as end-of-body → treats `SMUGGLED` as the beginning of the **next** request on the connection → it gets prepended to whoever's request comes next.

---

## 3. HTTP/2 downgrade smuggling — why it matters in 2026
HTTP/2 has an unambiguous, binary, length-prefixed framing — no CL/TE ambiguity *within* h2. **But** most CDNs speak HTTP/2 to the client and **downgrade to HTTP/1.1 to the origin.** During that rewrite, an attacker-controlled `content-length` or a smuggled `transfer-encoding` in an h2 request can produce an ambiguous h1 request at the origin. This is where most current, exploitable smuggling lives (James Kettle's "HTTP/2: The Sequel is Always Worse"). Also: **h2 request splitting** via CRLF injection in header values that the downgrade doesn't sanitise.

---

## 4. Impact — why it's severe (it attacks *other users*)
- **Capture another user's request** — smuggle a prefix that causes the victim's request (with their cookies/auth) to be stored and reflected back to you → **session/credential theft**.
- **Bypass front-end security controls** — the front-end enforces authz/WAF on the *visible* request; the smuggled request hidden in the body reaches the back-end unchecked → reach `/admin`, bypass blocks.
- **Web cache poisoning / deception** → [[Web-Cache-Poisoning]].
- **Response queue desync** — every subsequent user on that connection gets the wrong response, mass-affecting traffic.
- Turn an internal-only header (`X-Forwarded-For`, host routing) into an injection point.

## 5. Detection
- **Timing-based probes** (safest first test): a CL.TE payload that makes the back-end wait for more chunk data causes a measurable **delay**. TE.CL similarly.
  ```http
  POST / HTTP/1.1
  Host: x
  Transfer-Encoding: chunked
  Content-Length: 4

  1
  A
  X          ← back-end waiting for more → hang = TE processed
  ```
- **Differential responses** — confirm by smuggling a request that produces an observably different response for the *next* request.
- **Tooling:** Burp **HTTP Request Smuggler** extension (automated probes + the single-packet / h2 techniques). Test carefully — smuggling can affect *real users'* traffic, so only on authorized targets/labs.

## 6. The fix
- **Use HTTP/2 end-to-end** and don't downgrade to HTTP/1.1 at the back-end (removes the ambiguity class).
- **Make the front-end normalise/reject ambiguous requests:** reject any request with *both* `Content-Length` and `Transfer-Encoding`; reject obfuscated/duplicate TE headers; reject malformed h2→h1 rewrites.
- **Both hops must agree** on parsing — prefer the same server software / strict RFC-compliant parsers.
- Disable connection reuse to the back-end as a mitigation (perf cost) if you can't fix parsing.
- Keep front-end/CDN software patched — many smuggling issues are fixed proxy CVEs.

## 7. Real-world cases
- **PortSwigger / James Kettle research (2019 "HTTP Desync Attacks", 2021 "HTTP/2: The Sequel")** — the body of work that revived smuggling and found it on major sites; the canonical study material.
- Disclosed reports against **major CDNs, Slack, Atlassian, and numerous bug-bounty targets** — smuggling to hijack sessions and bypass controls, often four/five-figure bounties.
- Recurrent **CVEs in HAProxy, Nginx, Apache Traffic Server, Envoy** for request-parsing discrepancies.

## 8. Practice + interview questions

### Practice
- **PortSwigger Academy → HTTP request smuggling** — the full track (CL.TE, TE.CL, TE.TE obfuscation, h2 downgrade, exploiting to capture requests and bypass controls). Advanced but among the most rewarding labs they have.
- Use Burp's HTTP Request Smuggler on a lab; read what each probe sends.

### Interview questions
- *What fundamentally causes request smuggling?* (Front-end and back-end disagree on message-body length — CL vs TE — on a reused connection.)
- *Why is it high impact?* (It manipulates *other users'* requests: session theft, control/WAF bypass, cache poisoning — not just your own session.)
- *What's the modern HTTP/2 angle?* (h2 is unambiguous, but CDN→origin downgrade to h1 reintroduces ambiguity; H2.CL/H2.TE and h2 request splitting.)
- *How do you safely test for it?* (Timing probes first, then differential-response confirmation; only on authorized targets since it can affect real traffic.)
- *How do you fix it?* (HTTP/2 end-to-end, reject requests with both CL and TE / obfuscated TE, consistent RFC-strict parsing across hops.)

---

**Related:** [[HTTP-Deep-Dive]] · [[Web-Cache-Poisoning]] · [[Browser-Security-Model]]
