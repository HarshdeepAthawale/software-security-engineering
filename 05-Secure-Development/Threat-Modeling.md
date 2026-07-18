---
tags: [secure-dev, threat-modeling, a06]
owasp: A06:2025
status: learning
---

# Threat Modeling

> This is the skill that makes you an **AppSec Engineer** rather than a bug-finder. Anyone can run a scanner. Companies pay for someone who can look at a *design* and say "here's where this will be attacked, before you build it." Maps to **A06:2025 — Insecure Design**.

---

## The four questions (Shostack's framework — memorise)
1. **What are we building?** → draw it (data flow diagram)
2. **What can go wrong?** → find threats (STRIDE)
3. **What are we going to do about it?** → mitigations
4. **Did we do a good job?** → validate

That's the entire discipline. Everything else is tooling.

---

## Step 1: Data Flow Diagram (DFD)
Draw the system as: **external entities** (users, third parties), **processes** (services), **data stores** (DBs, queues, buckets), **data flows** (arrows), and — the critical part — **trust boundaries** (dashed lines where privilege/trust changes).

```
[User] ──HTTPS──▶ ⟦API Gateway⟧ ══trust boundary══▶ (Auth Service) ──▶ [(User DB)]
                                                    │
                                        ══boundary══▶ (Payment Service) ──▶ [Stripe]
```

**Threats concentrate at trust boundaries.** Every arrow crossing a dashed line is a place where data from a less-trusted zone enters a more-trusted one — i.e., where validation and authorization must happen. Train your eye to jump straight to the boundaries.

## Step 2: STRIDE — the threat taxonomy

| Letter | Threat | Violates | Example | Defence |
|---|---|---|---|---|
| **S** | Spoofing | Authentication | Fake a user/service identity | Strong authN, mutual TLS |
| **T** | Tampering | Integrity | Modify data in transit/at rest | Signatures, HMAC, TLS, input validation |
| **R** | Repudiation | Non-repudiation | "I never made that transfer" | Audit logs, signed receipts |
| **I** | Information disclosure | Confidentiality | Leak PII, keys | Encryption, access control, least data |
| **D** | Denial of service | Availability | Exhaust resources | Rate limits, quotas, autoscale |
| **E** | Elevation of privilege | Authorization | User → admin | AuthZ checks, least privilege |

Walk each element/flow and ask "how could each STRIDE letter apply here?" It's a checklist that forces completeness — you won't forget to consider tampering just because you were focused on auth.

## Step 3: Prioritise
Not all threats are equal. Rank by **impact × likelihood**. Use DREAD loosely or just a risk matrix. Tie each to a concrete mitigation and an owner — a threat model that doesn't produce **tickets** is a document nobody reads.

## Step 4: Validate
Did the mitigations get built? Add security tests. Re-model when the design changes materially. Threat models are living documents, not one-time PDFs.

---

## When to threat model
- **New feature design** — cheapest time to fix (a design change vs a re-architecture). This is the whole point of "shift left."
- Adding a new trust boundary (new third party, new data store)
- Handling new sensitive data (payments, health, PII)
- After a security incident (what class did we miss?)

## Lightweight in practice
Full formal STRIDE-per-element is heavy. In fast teams:
- **Threat modeling in a 45-min whiteboard session** per feature: draw the DFD, walk boundaries, list top 5 threats, file tickets.
- Tools: **OWASP Threat Dragon** (free, DFD + STRIDE), Microsoft Threat Modeling Tool, or `pytm` (threat model as code — great for a resume project).
- **"Evil user stories":** for each user story, write the attacker's version. "As an attacker, I want to read another user's invoices." Then check the design prevents it.

---

## Practice + interview
- **Threat model a real open-source app** (pick one on GitHub — a URL shortener, a note app). Produce a DFD + STRIDE table + prioritised mitigations as a PDF. **This is a resume project** — see [[Resume-Projects]].
- Do the same for a feature you use daily (password reset, file sharing).
- **Interview:** *Walk me through how you'd threat model a new payment feature.* (Four questions → DFD → boundaries → STRIDE per flow → prioritise → tickets → validate.) *What's the difference between Insecure Design and a coding bug?* (Design flaws can't be fixed by patching a line — the architecture is wrong; e.g., no rate limiting was ever designed in. That's why A06 exists separately.) *When in the SDLC is threat modeling most valuable?* (Design phase — fixes are 10–100× cheaper than post-release.)

---

**Related:** [[Secure-Design-Principles]] · [[Secure-Code-Review-Methodology]] · [[Resume-Projects]]
