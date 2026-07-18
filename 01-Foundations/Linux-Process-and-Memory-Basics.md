---
tags: [foundations, linux, systems]
status: learning
---

# Linux, Process & Memory Basics

> Web security sits on top of an OS. You don't need to be a kernel hacker, but understanding processes, permissions, and (lightly) memory makes RCE, privilege escalation, and container escapes make sense instead of feeling like magic.

## Linux fundamentals every security engineer needs
- **Permissions:** `rwx` for user/group/other; `chmod`/`chown`; **SUID/SGID** binaries (run as owner — a classic privesc vector; `find / -perm -4000`), sticky bit.
- **Users & privilege:** root (uid 0), `sudo`, `/etc/passwd` & `/etc/shadow`, capabilities (`CAP_SYS_ADMIN` ≈ root).
- **Processes:** `ps`, `/proc/<pid>/`, environment (`/proc/pid/environ` can leak secrets), file descriptors, signals.
- **Networking:** `ss`/`netstat`, listening ports, `iptables`/`nftables`, localhost vs 0.0.0.0 binding (why [[SSRF-Server-Side-Request-Forgery]] to `127.0.0.1` reaches internal services).
- **The shell:** how metacharacters (`;`, `|`, `` ` ``, `$()`) are interpreted — the mechanism behind [[Injection-Command-and-NoSQL]].
- **Isolation:** namespaces + cgroups = containers ([[Container-and-Kubernetes-Security]]); breaking them = container escape.

## Privilege escalation mindset (Linux)
From a low-priv shell, attackers look for: SUID binaries, writable `PATH`/scripts run by root, cron jobs, sudo misconfig (`sudo -l`), kernel exploits, exposed creds/keys, capabilities. Tools: **LinPEAS**, **GTFOBins** (how to abuse allowed binaries). Great to practice on TryHackMe/HTB.

## Memory safety (conceptual — know the vocabulary)
You likely won't write exploits day one, but you must recognize the classes and why memory-safe languages matter:
- **Buffer overflow** — write past a buffer → overwrite adjacent memory / return address → control flow hijack. Root cause of decades of RCE.
- **Use-after-free, double-free, integer overflow** → corruption → often RCE.
- **Mitigations:** ASLR, DEP/NX, stack canaries, CFI — and why they're layered (each raises the bar).
- **Why it matters in 2026:** ~70% of severe CVEs in big C/C++ codebases are memory-safety bugs. This is the entire industry argument for **Rust/Go/memory-safe languages** — a talking point you should have. (Note: memory-safe ≠ bug-free — logic/injection bugs remain, see [[Language-Specific-Pitfalls]].)

## Practice + interview
- Get comfortable in a Linux VM; do a few TryHackMe privesc rooms.
- `find / -perm -4000 2>/dev/null` — find SUID binaries; look one up on GTFOBins.
- **Interview:** *What's a SUID binary and why does it matter?* (Runs with owner's privileges → privesc if abusable.) *Why does everyone push memory-safe languages?* (~70% of critical C/C++ CVEs are memory-safety bugs; Rust/Go eliminate the class.) *What is a buffer overflow, conceptually?* (Writing past a buffer overwrites adjacent memory/return address → control hijack.)

---
**Related:** [[Injection-Command-and-NoSQL]] · [[Container-and-Kubernetes-Security]] · [[Language-Specific-Pitfalls]] · [[SSRF-Server-Side-Request-Forgery]]
