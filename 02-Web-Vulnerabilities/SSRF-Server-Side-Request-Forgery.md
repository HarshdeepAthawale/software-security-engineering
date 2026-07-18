---
tags: [vuln, web, a01, ssrf]
owasp: A01:2025
difficulty: medium-high
status: learning
---

# Server-Side Request Forgery (SSRF)

> **Moved into A01:2025 (Broken Access Control).** The reasoning: SSRF is the server making a request *on the attacker's behalf* to a destination it should not be authorized to reach. It's an access-control failure at the network layer. SSRF is a top cloud-era bug because the server usually sits inside a trusted network with access to metadata services, internal APIs, and databases the attacker can't reach directly.

---

## 1. What it actually is

The app takes a URL (or hostname, or anything that becomes one) from the user and **fetches it server-side**. The attacker controls the destination, so they make the server request things it shouldn't.

```
User submits:  https://evil.com/webhook          (intended: their own server)
Attacker submits: http://169.254.169.254/latest/meta-data/iam/security-credentials/
                  → server fetches cloud credentials and hands them back
```

---

## 2. Root cause

The server treats a **user-supplied destination** as trusted, and it makes requests from a **network position of privilege** (inside the VPC, able to reach `localhost`, the metadata endpoint, internal services with no auth). Two failures stacked: no destination validation + over-trusting internal network.

---

## 3. Where SSRF hides (it's rarely a field labelled "URL")

- Webhook / callback URL configuration
- "Import from URL", "fetch avatar from URL", link preview / unfurling
- PDF/screenshot/thumbnail generators (headless browser fetches your URL)
- Document converters, image processors (ImageMagick, `libxml`)
- XML parsers → [[XXE-and-XML-Attacks]] is an SSRF vector
- Any field that *becomes* a request: a `Host` header proxied onward, a `url=` redirect param fetched server-side, an OpenID/OAuth `redirect_uri` or JWKS URL the server retrieves
- File parsers that follow embedded references (SVG, PDF, DOCX)

**Blind SSRF** — the server fetches but you don't see the response. Still valuable: internal port scanning (via timing/errors), hitting internal state-changing endpoints, and exfil via DNS/HTTP to a server you control (Burp Collaborator / interactsh).

---

## 4. Exploitation targets

| Target | Payload | Prize |
|---|---|---|
| **AWS IMDSv1 metadata** | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | Temporary IAM creds → often account-wide access |
| **GCP metadata** | `http://metadata.google.internal/computeMetadata/v1/` (needs `Metadata-Flavor` header) | Service account tokens |
| **Azure IMDS** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (needs `Metadata: true`) | Managed identity tokens |
| **Localhost services** | `http://127.0.0.1:6379` (Redis), `:9200` (Elasticsearch), `:8080` admin panels | Unauthed internal admin |
| **Internal network** | `http://10.0.0.5/`, `http://internal-api/` | Reach services with no external exposure |
| **Cloud/k8s** | `http://169.254.169.254`, kubelet `:10250`, etcd | Cluster takeover |
| Non-HTTP schemes | `file:///etc/passwd`, `gopher://` (craft raw TCP → Redis/SMTP), `dict://` | File read, protocol smuggling |

> **The classic escalation:** SSRF → AWS metadata → IAM creds → `aws s3 ls` → data. This is the single most valuable SSRF chain and a favourite interview walk-through. See [[Chaining-Vulnerabilities]].
>
> **IMDSv2** requires a PUT to get a session token first, which most SSRF can't do — so "is IMDSv2 enforced?" is the key mitigation question. Many breaches (Capital One) predate/ignored it.

---

## 5. Filter bypasses — SSRF is a bypass game

Naive defences blocklist `127.0.0.1` and `localhost`. All of these evade that:

| Technique | Payload |
|---|---|
| Alternate localhost | `127.1`, `0.0.0.0`, `0`, `[::1]`, `127.0.0.2` |
| Decimal / octal / hex IP | `2130706433`, `0177.0.0.1`, `0x7f.0.0.1` |
| DNS pointing at internal | `attacker.com` → A record `169.254.169.254` |
| **DNS rebinding (TOCTOU)** | DNS resolves public at validation time, internal at fetch time |
| Enclosed alphanumerics / unicode | `①②⑦.0.0.1`, IDN tricks |
| Redirect | Your public URL 302-redirects to `http://169.254.169.254/` |
| URL parser confusion | `http://evil.com@169.254.169.254/`, `http://169.254.169.254#@evil.com/` |
| IPv6-mapped IPv4 | `[::ffff:169.254.169.254]` |
| Wrapped/short | `http://[::]`, trailing dots |

See the SSRF bypass table in the `security-arsenal` skill for the exhaustive list.

**Why blocklists fundamentally lose:** the parser that validates the URL and the client that fetches it are often *different parsers* that disagree — the exact same category of bug as [[HTTP-Request-Smuggling]]. And DNS rebinding beats any check done before the fetch, because resolution happens twice.

---

## 6. The fix

Layer these — no single one is sufficient:

1. **Allowlist destinations.** If webhooks only ever go to a known set of domains, enforce that. Allowlisting the *destination* beats blocklisting *bad IPs* every time.
2. **Resolve, validate, then pin.** Resolve the hostname yourself, reject the request if it maps to a private/link-local/loopback/reserved range, then **connect to that validated IP** (don't re-resolve) to defeat DNS rebinding.
3. **Block cloud metadata explicitly** and require **IMDSv2** (or disable IMDS if unused). This alone would have stopped several major breaches.
4. **Disable dangerous schemes** — only allow `http`/`https`; kill `file://`, `gopher://`, `dict://`, `ftp://`.
5. **Don't follow redirects** blindly — re-validate the target of every redirect hop.
6. **Network egress control** — the fetching service should live in a subnet with a deny-by-default egress policy. This is the defence-in-depth that saves you when validation is bypassed.
7. **Never reflect the raw response** to the user if you can avoid it (limits blind→full escalation).

```python
import ipaddress, socket
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network(n) for n in
    ("127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
     "169.254.0.0/16","::1/128","fc00::/7","fe80::/10")]

def safe_fetch_target(url):
    u = urlparse(url)
    if u.scheme not in ("http","https"):
        raise ValueError("scheme")
    ip = socket.gethostbyname(u.hostname)          # resolve once
    addr = ipaddress.ip_address(ip)
    if any(addr in net for net in BLOCKED):
        raise ValueError("blocked range")
    return ip   # ← connect to THIS ip, do not re-resolve (anti-rebinding)
```

---

## 7. Real-world cases

- **Capital One (2019)** — the defining SSRF breach. SSRF in a misconfigured WAF → EC2 metadata (IMDSv1) → IAM role creds → S3 → **~100M customers**. Directly motivated IMDSv2. Learn this one cold; it's asked constantly.
- **GitLab, GitHub, Shopify** — many disclosed SSRFs via webhook/import features and link previews; high bounties.
- **MS Exchange SSRF (CVE-2021-26855, "ProxyLogon")** — pre-auth SSRF chained to RCE; mass-exploited globally.
- **Grafana, various CVEs** — SSRF via URL-fetching features is a perennial appliance bug.

---

## 8. Practice + interview questions

### Practice
1. **PortSwigger Academy → SSRF** — all labs, including the blind ones and the filter-bypass labs.
2. Build a "fetch avatar from URL" endpoint, exploit it against a local metadata mock (`169.254.169.254`), then apply the allowlist+resolve+pin fix and defeat your own bypasses.
3. Set up a DNS rebinding demo with a rebinding service — this makes the TOCTOU click.
4. Practice the full Capital-One-style chain in a cloud lab (e.g., an IMDSv1-enabled test instance you own).

### Interview questions
- *What is SSRF and why is it so dangerous in the cloud?* (Server fetches attacker-chosen URL from a privileged network position → metadata service, internal APIs. Walk the Capital One chain.)
- *Why did OWASP move SSRF under Broken Access Control in 2025?* (It's the server making an unauthorized request on the attacker's behalf — access control at the network layer.)
- *A dev blocks `127.0.0.1` and `localhost`. Bypass it.* (Decimal/hex IP, `[::1]`, DNS record pointing internal, redirect, DNS rebinding, `@`-in-URL parser confusion.)
- *How do you actually fix SSRF?* (Allowlist destinations; resolve-validate-pin to beat rebinding; block metadata + enforce IMDSv2; restrict schemes; no blind redirect-following; egress firewall. Emphasise layers.)
- *What's IMDSv2 and why does it matter?* (Session-token-required metadata access via a PUT preflight — most SSRF primitives can't perform it, so it neutralises the metadata-theft escalation.)

---

**Related:** [[Broken-Access-Control-IDOR]] (same A01 category) · [[XXE-and-XML-Attacks]] (an SSRF vector) · [[Cloud-Security-AWS-Focus]] · [[Chaining-Vulnerabilities]]
