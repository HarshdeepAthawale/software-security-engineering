---
tags: [job, detection, logging, a09]
owasp: A09:2025
status: learning
---

# Detection, Logging & Response

> **A09:2025 — Security Logging and Alerting Failures.** You can't respond to what you can't see. Prevention fails eventually; detection is what turns "breach" into "blocked attempt." AppSec engineers design *what* to log and *what should alert*.

## What to log (security-relevant events)
- AuthN: logins (success/fail), logouts, password/MFA changes, resets
- AuthZ: access-denied events, privilege changes, admin actions
- Input validation failures, WAF blocks
- High-value actions: payments, data exports, config/permission changes, account deletion
- Anomalies: rate-limit trips, new-device/geo logins

## How to log it (get this right or the logs are useless — or dangerous)
- **Enough context:** who (user id), what, when (UTC), where (IP, endpoint), outcome. A "login failed" with no username/IP is worthless.
- **Never log secrets/PII in the clear** — passwords, tokens, card numbers, session IDs. Logging a password *is itself a vulnerability*.
- **Prevent log injection/forging** — user input in logs must be encoded (CRLF → forged entries; and Log4Shell was a *logging* RCE — `${jndi:...}`). → [[Injection-Command-and-NoSQL]].
- **Tamper-resistant** — centralized, append-only, off the host an attacker just compromised.
- **Consistent, parseable** format (structured JSON).

## Detection & alerting
- Centralize → SIEM (Splunk, Elastic, cloud-native like GuardDuty/Sentinel).
- **Alert on the meaningful, not the noisy** — brute-force patterns, privilege escalation, impossible travel, mass data access, known-bad IOCs. Alert fatigue kills detection programs as surely as no alerts.
- Detection-as-code: Sigma rules, tested in CI.
- Tie back to [[Threat-Modeling]] — for each threat, ask "would we detect this?"

## Incident response basics (the lifecycle)
**Prepare → Detect → Contain → Eradicate → Recover → Lessons learned.** As AppSec you feed detection and often the "how did they get in / what's the code fix" parts. Post-incident: root-cause the *class* and prevent recurrence.

## The A09 failure modes
- No logging on security events
- Logs not monitored / no alerting (breach dwell time in the *months*)
- Logs only local (wiped by the attacker)
- Sensitive data logged in clear
- No response plan → chaos when it matters

## Interview
- *What should you log for security, and what must you never log?* (Auth/authz/high-value events with context; never passwords/tokens/PII.) *Why is logging a Top 10 category?* (Undetected breaches = massive dwell time; you can't respond to what you don't see.) *What's log injection?* (Unescaped user input forging/attacking log entries — Log4Shell was logging-triggered RCE.) *Walk the IR lifecycle.* (Prepare→Detect→Contain→Eradicate→Recover→Lessons.)

---
**Related:** [[Threat-Modeling]] · [[Vulnerability-Management-and-Triage]] · [[Cloud-Security-AWS-Focus]]
