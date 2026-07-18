---
tags: [job, tooling, appsec]
status: learning
---

# SAST, DAST, SCA & Security Tooling

> An AppSec engineer *runs, tunes, and triages* these tools — and knows their limits. The job isn't "run scanner, forward output"; it's separating the 5 real bugs from the 500 false positives, and knowing what each tool structurally cannot find.

## The categories
| Type | What it does | Finds | Blind to |
|---|---|---|---|
| **SAST** (static) | Analyzes source/bytecode without running it | Injection sinks, hardcoded secrets, known bad patterns | Business logic, authz, runtime/config issues; noisy |
| **DAST** (dynamic) | Attacks the running app black-box | Reflected issues, some injection, misconfig, live behavior | Source-level nuance, code paths not exercised; needs coverage |
| **IAST** | Instruments the running app (agent) | Combines both, lower FP | Runtime overhead, language support |
| **SCA** | Scans dependencies for known CVEs | Vulnerable/outdated libs, license issues | Your own code, zero-days |
| **Secret scanning** | Regex/entropy over code + history | Committed keys/tokens | Secrets only in runtime env |
| **Fuzzing** | Malformed inputs at scale | Crashes, memory bugs, edge cases | Needs harness; mostly for parsers/native code |

**No single tool is enough** — layer them, and none replaces a human ([[Secure-Code-Review-Methodology]]).

## The tools to actually know
- **Semgrep** ⭐ — fast, writeable custom rules, low friction. **Learn to write rules** — it's a resume differentiator ([[Resume-Projects]]).
- **CodeQL** — powerful semantic queries (treats code as a database); GitHub-native.
- **Burp Suite / Caido** — the DAST/manual-testing workhorse ([[Lab-Environment-Setup]]).
- **Nuclei** — templated vuln scanning; huge community template set.
- **Trivy / Grype** — SCA + container + IaC scanning.
- **gitleaks / trufflehog** — secret scanning (run on full git history).
- **OWASP ZAP** — free DAST.
- **Dependabot / Renovate** — automated dep updates.

## Writing a Semgrep rule (do this — it teaches you *and* impresses)
```yaml
rules:
  - id: python-requests-no-verify
    pattern: requests.$METHOD(..., verify=False, ...)
    message: TLS verification disabled — MITM risk
    severity: ERROR
    languages: [python]
```
Then: rules for missing authz decorators, `shell=True`, `render_template_string`, `pickle.loads`. → 3–10 of these = Resume Project #3.

## Integrating into CI (the DevSecOps job)
- Run SAST/SCA/secret-scan on every PR; **fail the build on high-severity**.
- **Tune ruthlessly** — a scanner that cries wolf gets ignored by devs. Suppress FPs with justification; measure signal.
- Give devs findings *in their workflow* (PR comments), with fixes.
- This whole pipeline is [[CI-CD-and-Software-Supply-Chain]] Resume Project #1.

## The honest limitations (say these in interviews)
- SAST can't understand your business rules → misses [[Broken-Access-Control-IDOR]] and [[Business-Logic-Flaws]] (the #1 real bugs).
- DAST only tests what it reaches → coverage gaps.
- **False positives are the tax**; triage is the skill. High-signal tuning > more scanners.

## Interview
- *SAST vs DAST vs SCA — when each?* (Static/source early; dynamic against running app; SCA for deps. Layer them.) *What can't a scanner find?* (Authz/IDOR, business logic — no rule knowledge; that's why humans review.) *How do you handle false positives?* (Tune rules, suppress with justification, measure signal, protect dev trust.) *Have you written a SAST rule?* (Yes — show your Semgrep pack.)

---
**Related:** [[Secure-Code-Review-Methodology]] · [[CI-CD-and-Software-Supply-Chain]] · [[Vulnerability-Management-and-Triage]] · [[Resume-Projects]]
