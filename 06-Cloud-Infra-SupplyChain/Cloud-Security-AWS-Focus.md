---
tags: [cloud, aws, a02]
owasp: A02:2025
status: learning
---

# Cloud Security (AWS Focus)

> Most modern breaches are cloud misconfigurations, not zero-days. AWS is the market leader, so learn it deeply; the concepts transfer to GCP/Azure. Maps to **A02:2025 — Security Misconfiguration**.

## IAM — the heart of AWS security
Everything is identity + policy. Get IAM wrong and nothing else matters.
- **Principals** (users, roles), **policies** (JSON allow/deny), **roles** (assumable identities — prefer these over long-lived user keys).
- **Least privilege**: the #1 mistake is `"Action": "*", "Resource": "*"`. Scope actions and resources tightly.
- **Privilege escalation paths**: `iam:PassRole` + `iam:CreatePolicyVersion`, `sts:AssumeRole` chains, `lambda:UpdateFunctionCode`. Tools: **pmapper**, **PACU**, **ScoutSuite** enumerate these.
- **Trust policies** on roles — who can assume this role? A wildcard/external-account trust = takeover.

## The classic misconfigs
| Service | Misconfig | Impact |
|---|---|---|
| **S3** | Public bucket / bucket policy `*` | Mass data exposure (the canonical cloud breach) |
| **IAM** | Over-broad policies, long-lived keys | Priv-esc, lateral movement |
| **EC2 metadata (IMDSv1)** | SSRF → creds | → [[SSRF-Server-Side-Request-Forgery]] (Capital One). **Enforce IMDSv2** |
| **Security Groups** | `0.0.0.0/0` on 22/3389/DB ports | Direct internet exposure |
| **RDS** | Publicly accessible DB | Data theft |
| **Secrets** | Keys in EC2 user-data, env, AMIs | → [[Secrets-Management]] |
| **KMS / logging** | No encryption, CloudTrail off | No detection ([[Detection-Logging-and-Response]]) |
| **Lambda** | Over-privileged execution role | Blast radius |

## The shared responsibility model
AWS secures *the cloud* (hardware, hypervisor); **you** secure *in the cloud* (your IAM, data, configs, patching). Nearly every "cloud breach" is the customer's side. Know this framing — it's asked constantly.

## Defenses
- **Least-privilege IAM**, no long-lived keys — use roles + short-lived creds / OIDC ([[Secrets-Management]]).
- **Enforce IMDSv2**, disable IMDS where unused.
- **Block Public Access** on S3 org-wide; encrypt at rest (KMS) + in transit.
- **CloudTrail + GuardDuty + Config** on, centralized, alerting.
- **Automated posture scanning**: ScoutSuite, Prowler, CloudSploit, Steampipe.
- Tighten security groups; private subnets + no public DBs; VPC egress control (also mitigates SSRF).
- Guardrails: SCPs (Organizations), least-privilege by default.

## Practice + interview
- **flaws.cloud** and **flaws2.cloud** — free, brilliant guided AWS-security walkthroughs. Do both.
- **CloudGoat** — deploy vulnerable scenarios in your own account and exploit them.
- Run **Prowler/ScoutSuite** against a test account; read every finding.
- **Interview:** *Explain the shared responsibility model.* *Most common cloud breach cause?* (Misconfig — public S3, over-broad IAM — not zero-days.) *How does SSRF become critical in AWS?* (Metadata creds → IAM → data; enforce IMDSv2.) *How do you scope IAM to least privilege and detect escalation?* (Tight action/resource, no `*`, avoid dangerous combos like `iam:PassRole`, scan with pmapper/Prowler.)

---
**Related:** [[SSRF-Server-Side-Request-Forgery]] · [[Container-and-Kubernetes-Security]] · [[Secrets-Management]] · [[Detection-Logging-and-Response]] · `bug-bounty` cloud-misconfig section
