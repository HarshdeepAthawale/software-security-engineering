---
tags: [cloud, supply-chain, a03]
owasp: A03:2025
status: learning
---

# CI/CD & Software Supply Chain Security

> **A03:2025 — Software Supply Chain Failures.** Brand-new Top 10 category (2025), reflecting SolarWinds, Log4Shell, the xz backdoor, and the endless stream of npm/PyPI malware. Fluency here in 2026 is a real differentiator — most engineers still think "supply chain = run `npm audit`." It's much more.

---

## The attack surface (it's the whole path from code to production)
```
[Your code] → [Dependencies] → [Build system/CI] → [Artifact/registry] → [Deploy] → [Prod]
     every arrow is an injection point
```

### 1. Dependency attacks
| Attack | Mechanism |
|---|---|
| **Known-vulnerable deps** | Using a package with a public CVE (Log4Shell = Log4j CVE-2021-44228) |
| **Typosquatting** | `reqeusts`, `python-dateutil` vs `dateutil` — malware on a near-miss name |
| **Dependency confusion** | Internal package name `acme-utils` not claimed on public PyPI → attacker publishes it public with a higher version → your build pulls the attacker's |
| **Malicious maintainer / hijack** | Legit package updated with malware (event-stream 2018; xz backdoor 2024) |
| **Compromised transitive dep** | The dep of your dep of your dep |
| **Install-time code execution** | `postinstall` scripts, `setup.py` running on `pip install` |

### 2. CI/CD pipeline attacks
| Attack | Mechanism |
|---|---|
| **Poisoned pipeline execution (PPE)** | Malicious code in a PR runs in CI with secrets access |
| **Leaked CI secrets** | Tokens/keys in logs, env, or exfiltrated by a malicious dependency at build time |
| **Compromised build = compromised everyone** | SolarWinds: build server injected a backdoor into signed updates → 18,000 orgs |
| **Unpinned actions** | `uses: some/action@main` pulls whatever `main` is *now* — could be backdoored |
| **Self-hosted runner abuse** | Persistent runners retain state/secrets between jobs |
| **Artifact tampering** | Unsigned artifacts swapped between build and deploy |

---

## Defences (this is a great resume pipeline to build)

| Control | Tool | Stops |
|---|---|---|
| **SCA** — scan deps for CVEs | Trivy, Grype, `npm audit`, Dependabot | Known-vulnerable deps |
| **Lockfiles + integrity hashes** | `package-lock.json`, `pip --require-hashes`, `poetry.lock` | Silent version swaps, some confusion |
| **Pin everything** | Pin action SHAs, base image digests, dep versions | Unpinned-ref backdoors |
| **Scope internal packages** | Private registry, namespace/scope, claim public names | Dependency confusion |
| **SBOM generation** | Syft, CycloneDX, SPDX | "What are we even running?" — needed to respond to the *next* Log4Shell in minutes |
| **Artifact signing / provenance** | Sigstore/cosign, **SLSA** framework, in-toto | Tampering; proves *where/how* an artifact was built |
| **Secret scanning** | gitleaks, trufflehog (on history) | Leaked creds |
| **Least-privilege CI** | Scoped tokens, OIDC not long-lived keys, ephemeral runners | Blast radius of a pipeline compromise |
| **Disable install scripts** where feasible | `npm ci --ignore-scripts` | Install-time RCE |

**Know these frameworks by name (interviewers check):**
- **SLSA** (Supply-chain Levels for Software Artifacts) — a maturity model for build integrity/provenance.
- **SBOM** (Software Bill of Materials) — the ingredient list; SPDX / CycloneDX formats.
- **Sigstore/cosign** — keyless signing of artifacts.
- **in-toto**, **SLSA provenance** — attestations that an artifact was built as claimed.

---

## Real-world (study these — they define the category)
- **SolarWinds (2020)** — build system compromised → malicious code in signed Orion updates → ~18,000 orgs, incl. US federal agencies. The reason A03 exists.
- **Log4Shell (2021, CVE-2021-44262... 44228)** — trivial RCE in ubiquitous Log4j; the world learned it had no SBOMs and couldn't answer "are we affected?"
- **xz/liblzma backdoor (2024, CVE-2024-3094)** — a multi-year social-engineering campaign put a backdoor into a core Linux compression lib; caught by luck (a Postgres perf anomaly). The scariest supply-chain story yet.
- **Codecov (2021)** — CI script compromise exfiltrated secrets from thousands of pipelines.
- Ongoing npm/PyPI malware — new malicious packages published weekly.

---

## Practice + interview (resume project)
- **Build a hardened GitHub Actions pipeline** for a sample app: Semgrep (SAST) + Trivy (SCA + container scan) + gitleaks (secrets) + Syft (SBOM) + cosign (signing), with pinned action SHAs and OIDC auth. Put it on GitHub. **This is a strong resume project** — see [[Resume-Projects]].
- Reproduce a **dependency confusion** setup in a lab (internal name unclaimed publicly).
- Generate and diff an SBOM for a real project; simulate responding to a new CVE using it.
- **Interview:** *What's dependency confusion and how do you prevent it?* (Public/private namespace collision + version resolution; claim your names, scope the registry, pin.) *SolarWinds — what class was it?* (Build-system compromise → trusted-signed malware; the reason provenance/SLSA matters.) *What's an SBOM and why do you want one?* (Ingredient list; lets you answer "are we affected by CVE-X?" in minutes not weeks.) *How do you secure a CI pipeline that runs untrusted PR code?* (Don't expose secrets to PR-triggered jobs, ephemeral runners, least-priv OIDC tokens, require approval for workflow runs from forks.)

---

**Related:** [[Cloud-Security-AWS-Focus]] · [[SAST-DAST-SCA-and-Tooling]] · [[Container-and-Kubernetes-Security]] · `python-dependency-threat-scan` skill
