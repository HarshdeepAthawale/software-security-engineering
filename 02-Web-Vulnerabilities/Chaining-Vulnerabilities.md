---
tags: [vuln, web, chaining, methodology]
status: learning
---

# Chaining Vulnerabilities

> Real high-impact findings are usually **chains**: bug A alone is medium, but A→B→C is critical. Learning to chain is what turns a lab-solver into an operator — and it's what wins the big bounties and impresses interviewers. You have a dedicated **`chain` skill** (`/chain`) that automates finding B and C given A.

## Why chains matter
A single low/medium bug is often dismissed. Chained, the *impact* (which is what severity is really about — [[Vulnerability-Management-and-Triage]]) jumps to critical. Always ask of any finding: **"what does this unlock?"**

## Canonical chains (memorise the shapes)
| Chain | Path | Result |
|---|---|---|
| **IDOR → ATO** | Change victim's email via IDOR → trigger password reset → own account | Account takeover |
| **SSRF → cloud metadata → IAM → S3** | SSRF to `169.254.169.254` → creds → data | Full data breach (Capital One) → [[SSRF-Server-Side-Request-Forgery]] |
| **XSS → ATO** | Stored XSS → ride session / steal token → change credentials | Account takeover → [[XSS-Cross-Site-Scripting]] |
| **Open redirect → OAuth token theft** | Loose `redirect_uri`/open redirect → steal `code`/token | ATO → [[OAuth2-and-OIDC]] · [[Open-Redirect]] |
| **Subdomain takeover → cookie theft** | Dangling DNS → claim subdomain → same-site cookie access | Session theft |
| **S3 bucket → source bundle → hardcoded secret → API/OAuth** | Public bucket → JS/source → key → escalate | Deep compromise → [[Secrets-Management]] |
| **File upload → stored XSS / RCE** | SVG upload → XSS; or webshell → RCE | Varies → [[Path-Traversal-and-File-Upload]] |
| **Info leak → IDOR** | Leak of another user's object id → IDOR to read it | Data access |
| **Prompt injection → tool abuse → exfil** | Indirect injection → agent tool call → data out | AI-era chain → [[LLM-and-AI-Application-Security]] |

## The chaining mindset
1. **For every bug, ask what it gives you** — a primitive (read? write? redirect? execute? leak?).
2. **Map primitives to next steps** — a write primitive near auth data → ATO; a fetch primitive → SSRF targets.
3. **Look for the pivot** — the small info leak that makes the "unexploitable" bug exploitable (an id, a token, a path).
4. **Think in impact, report the whole chain** — the report should tell the end-to-end story ([[Report-Template]]).

## Practice + interview
- Use the **`chain` skill** on your lab findings; study disclosed HackerOne reports (the great ones are almost all chains).
- **Interview:** *Walk me through a vulnerability chain you'd build from an IDOR that changes email.* (→ reset → ATO.) *You have a blind SSRF — is it useless?* (No — internal port scan, metadata creds, hit internal endpoints, OOB exfil; chain to cloud takeover.) *Why report chains instead of individual bugs?* (Severity is impact-driven; the chain demonstrates real-world criticality a single bug doesn't.)

---
**Related:** every note in `02-Web-Vulnerabilities` · [[Vulnerability-Management-and-Triage]] · `chain` skill · `bug-bounty` skill (A-to-B chaining)
