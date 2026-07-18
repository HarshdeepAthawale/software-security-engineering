---
tags: [secure-dev, code-review]
status: learning
---

# Secure Code Review Methodology

> The daily work of an AppSec engineer. You'll review PRs, audit repos, and triage scanner output. The skill is **finding the 3 lines that matter in 10,000** — efficiently, and without annoying developers.

---

## The mindset: follow the data
Every serious web vuln is **untrusted data reaching a dangerous operation without adequate control.** So you trace **sources → sinks**.

```
SOURCES (untrusted input)          SINKS (dangerous operations)
─────────────────────────          ────────────────────────────
HTTP params / body / headers       SQL query           → SQLi
cookies                            HTML output         → XSS
file uploads                       OS command          → command injection
external API responses             file path           → path traversal
message queue payloads             deserializer        → insecure deser
DB values (second-order!)          template render     → SSTI
                                   URL fetch           → SSRF
                                   LDAP / XPath query  → injection
```

For any sink, ask: **can attacker-controlled data reach here, and is it neutralised on the way?** If yes/no → finding.

---

## The efficient pass order (don't read top-to-bottom)

1. **Map the attack surface first.** Find the routes/controllers/handlers — every entry point where external data arrives. Start there, not at `main()`.
2. **Authentication & authorization.** For each route: is it authenticated? Is it *authorized* (ownership/role)? This is where [[Broken-Access-Control-IDOR]] — the #1 real finding — lives. Look for the *absence* of checks, which is harder than spotting a bad one.
3. **Grep for dangerous sinks**, then trace each backward:
   ```bash
   # injection sinks
   grep -rnE "execute\(|query\(|\.raw\(|eval\(|exec\(|system\(|subprocess|os\.popen|child_process|Runtime.exec" .
   # deserialization
   grep -rnE "pickle.loads|yaml.load\(|Marshal.load|ObjectInputStream|unserialize\(|JSON.parse\(.*eval" .
   # rendering / xss
   grep -rnE "innerHTML|dangerouslySetInnerHTML|v-html|render_template_string|\|safe|Markup\(" .
   # secrets
   grep -rnE "(password|secret|api_?key|token|aws_.*key)\s*[:=]\s*['\"]" .
   # crypto misuse
   grep -rnE "MD5|SHA1|ECB|verify=False|InsecureSkipVerify|Math.random|random\.(rand|choice)" .
   # ssrf
   grep -rnE "requests\.(get|post)\(|urllib|http.get|fetch\(|HttpClient" .
   ```
4. **Config & secrets.** `.env`, CI files, IaC, Dockerfiles. Hardcoded creds, `DEBUG=true`, permissive CORS, disabled TLS verification, wildcard IAM.
5. **Dependencies.** `package.json`/`requirements.txt`/`go.mod` → known CVEs (SCA), and for A03:2025, *how* they're pulled (see [[CI-CD-and-Software-Supply-Chain]]).
6. **The security-critical flows specifically:** login, password reset, session handling, payment, file upload, admin functions, anything with money or PII.

---

## What separates a good reviewer

- **Prove exploitability, don't pattern-match.** "You used `innerHTML`" is noise if the input is a hardcoded constant. Trace whether *attacker* data actually reaches it. Unprovable findings destroy your credibility with devs.
- **Look for the missing thing.** Bugs of *omission* (no authz check, no rate limit, no output encoding) are harder and more valuable than bugs of *commission*.
- **Understand the framework's defaults.** Django autoescapes; React escapes; Spring has CSRF on by default. Knowing the default tells you where someone had to *opt out* — and opt-outs are where bugs cluster (`|safe`, `dangerouslySetInnerHTML`, `@csrf_exempt`).
- **Second-order data flows.** Data that's safe when stored but dangerous when later used (a username saved at signup, concatenated into an admin SQL report). Scanners miss these; humans catch them.

## Communicating findings (this is half the job)
For each finding: **what, where (`file:line`), why it's exploitable (concrete scenario), severity, and the fix (with code).** Be specific and kind — the developer is your collaborator, not your adversary. A finding that makes a dev defensive doesn't get fixed. Frame it as "here's a risk and here's how we close it," never "you screwed up."

Use the [[Report-Template]] structure even for internal PR comments.

## Tooling (augments, never replaces, the human)
- **SAST**: Semgrep (write custom rules — resume gold), CodeQL. High false positives; you triage.
- **SCA**: dependency scanning for known CVEs.
- **Secret scanning**: gitleaks, trufflehog — run on full git *history*, not just HEAD.
- See [[SAST-DAST-SCA-and-Tooling]].

---

## Practice + interview
- Review a deliberately-vulnerable app's source (Juice Shop, DVWA, or a "vulnerable-by-design" GitHub repo) top to bottom and produce a findings report.
- Do real PR reviews on OSS — even a couple of thoughtful security comments on GitHub is portfolio material.
- Write 3 custom Semgrep rules for patterns in a real codebase.
- **Interview (very common — they'll show you code):** *Here's a function — what's wrong?* Talk through source→sink out loud. *How do you review 50k lines efficiently?* (Attack surface first → authz → grep sinks → trace → config/deps → critical flows. You don't read linearly.) *How do you avoid false positives?* (Prove the data flow reaches the sink with attacker control; know framework defaults.)

---

**Related:** [[Threat-Modeling]] · [[Broken-Access-Control-IDOR]] · [[Language-Specific-Pitfalls]] · [[SAST-DAST-SCA-and-Tooling]] · `security-audit` skill
