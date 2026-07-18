---
tags: [secure-dev, secrets, a02]
owasp: A02:2025
status: learning
---

# Secrets Management

> Hardcoded and leaked secrets are one of the most common real findings, and among the easiest to prevent. Maps to **A02:2025 — Security Misconfiguration** (and feeds many breaches). A leaked key is often a straight line to full compromise.

## The problem
```python
AWS_SECRET = "AKIA...."          # ❌ in source
DB_PASSWORD = "prod_password_1"  # ❌ committed to git
```
Once a secret hits git history, it's compromised **forever** — even if you delete it in a later commit, it's in the history, in clones, in forks, and likely already scraped. Rotate, don't just delete.

## Where secrets leak
- Source code, committed `.env`, config files
- **Git history** (the classic — scan the whole history, not HEAD)
- CI/CD logs, build artifacts, Docker image layers
- Frontend JS bundles (API keys shipped to the browser)
- Error messages / stack traces, debug endpoints
- Public S3 buckets, backups, Slack/tickets

## The fix (hierarchy)
1. **Never in source.** Inject at runtime via environment or a secrets manager.
2. **Secrets manager** — AWS Secrets Manager / HashiCorp Vault / GCP Secret Manager / Azure Key Vault. Central, audited, **rotatable**, access-controlled.
3. **Short-lived credentials over static keys** — OIDC federation in CI (no long-lived cloud keys at all), IAM roles, workload identity. This is the modern best practice: eliminate static secrets entirely where possible.
4. **Scan continuously** — gitleaks/trufflehog in pre-commit hooks *and* CI (on full history). Your `web2-recon` skill watches GitHub commits for leaks on targets.
5. **Rotate on exposure**, immediately — assume any leaked secret is already used.
6. **Least privilege** on every secret — a leaked key should unlock as little as possible ([[Secure-Design-Principles]]).

## For the frontend
Anything shipped to the browser is public. "Secret" keys in JS aren't secret. Use a backend proxy; scope any unavoidable public keys (e.g. publishable/restricted API keys) tightly.

## Practice + interview
- Run gitleaks against a repo's full history; set up a pre-commit hook.
- Build a project using a secrets manager + OIDC instead of static keys → ties into [[Resume-Projects]] / [[CI-CD-and-Software-Supply-Chain]].
- **Interview:** *A secret got committed and removed in the next commit — is it safe?* (No — it's in history/clones/forks; rotate immediately.) *How do you manage secrets properly?* (Out of source, secrets manager, short-lived/OIDC creds, scanning, rotation, least privilege.) *Where do secrets commonly leak that people forget?* (Git history, Docker layers, frontend bundles, CI logs.)

---
**Related:** [[CI-CD-and-Software-Supply-Chain]] · [[Cloud-Security-AWS-Focus]] · [[Secure-Design-Principles]]
