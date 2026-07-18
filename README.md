# Security Engineering Vault

A self-directed curriculum for becoming a **Software / Application Security Engineer**.

Built around **[OWASP Top 10:2025](https://owasp.org/Top10/2025/)** (final release January 2026), not the outdated 2021 list.

---

## Start Here

- [[Roadmap]] — the 6-month plan, week by week
- [[How-To-Use-This-Vault]] — study method, spaced repetition, note conventions
- [[Resume-Projects]] — 6 portfolio projects that actually get interviews

---

## Map of Content

### 01 — Foundations
The mental models everything else hangs off. Do not skip.
- [[HTTP-Deep-Dive]]
- [[Browser-Security-Model]]
- [[Cryptography-Fundamentals]]
- [[Authentication-vs-Authorization]]
- [[Linux-Process-and-Memory-Basics]]

### 02 — Web Vulnerability Classes
Root cause → find it → exploit it → fix it.
- [[Broken-Access-Control-IDOR]] — *A01, the #1 risk*
- [[Injection-SQLi]]
- [[Injection-Command-and-NoSQL]]
- [[XSS-Cross-Site-Scripting]]
- [[SSRF-Server-Side-Request-Forgery]]
- [[CSRF-Cross-Site-Request-Forgery]]
- [[XXE-and-XML-Attacks]]
- [[SSTI-Template-Injection]]
- [[Insecure-Deserialization]]
- [[Path-Traversal-and-File-Upload]]
- [[Race-Conditions]]
- [[HTTP-Request-Smuggling]]
- [[Web-Cache-Poisoning]]
- [[Open-Redirect]]
- [[Business-Logic-Flaws]]
- [[Chaining-Vulnerabilities]]

### 03 — Identity & Access
- [[OAuth2-and-OIDC]]
- [[JWT-Attacks]]
- [[Session-Management]]
- [[MFA-and-Account-Recovery-Bypass]]

### 04 — Modern Stacks
- [[API-Security-OWASP-API-Top-10]]
- [[GraphQL-Security]]
- [[LLM-and-AI-Application-Security]]

### 05 — Secure Development
- [[Threat-Modeling]]
- [[Secure-Design-Principles]]
- [[Secrets-Management]]
- [[Language-Specific-Pitfalls]]
- [[Secure-Code-Review-Methodology]]

### 06 — Cloud, Infra & Supply Chain
- [[Cloud-Security-AWS-Focus]]
- [[Container-and-Kubernetes-Security]]
- [[CI-CD-and-Software-Supply-Chain]] — *A03:2025, brand new category*

### 07 — Doing the Job
- [[SAST-DAST-SCA-and-Tooling]]
- [[Vulnerability-Management-and-Triage]]
- [[Detection-Logging-and-Response]]

### 08 — Labs
- [[Lab-Environment-Setup]]
- [[Lab-Index]]

### 09 — Career
- [[Resume-Playbook]]
- [[Interview-Prep]]
- [[Certifications-and-Learning-Resources]]

---

## Conventions used in every vuln note

Each vulnerability note follows the same 8 sections so your brain builds one reusable pattern:

1. **What it actually is** — plain language
2. **Root cause** — the developer mistake underneath
3. **Vulnerable code** — real snippets, multiple languages
4. **How to find it** — grep patterns, code review questions, black-box tests
5. **Exploitation** — payloads and escalation
6. **The fix** — with fixed code
7. **Real-world cases** — CVEs and disclosed bug bounty reports
8. **Practice + interview questions**

---

## Progress Tracker

```dataview
TABLE status, difficulty
FROM "02-Web-Vulnerabilities"
SORT file.name ASC
```
*(Requires the Dataview plugin — see [[How-To-Use-This-Vault]])*
