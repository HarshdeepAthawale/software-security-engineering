---
tags: [vuln, web, a05, injection]
owasp: A05:2025
difficulty: medium-high
status: learning
---

# Command, NoSQL & Other Injection

> Same root cause as [[Injection-SQLi]] — data crossing into a code/command context — different sinks. OS command injection is often the highest-impact (direct RCE); NoSQL injection surprises devs who thought leaving SQL behind left injection behind.

## OS Command Injection → RCE
User input reaches a shell.
```python
# ❌
os.system(f"ping -c 1 {host}")
subprocess.run(f"convert {filename} out.png", shell=True)   # shell=True is the danger
```
```
Payloads:  ; id     | id     `id`     $(id)     %0a id     & id     || id
```
**Fix:** never call a shell with user input. Pass an **argument array** and no shell:
```python
subprocess.run(["ping", "-c", "1", host])   # ✅ no shell=True; host can't inject
```
If you *must* build a command, allowlist the input strictly. Blocklisting shell metacharacters is a losing game.

## NoSQL Injection (MongoDB etc.)
Injection via **operators**, not quotes.
```javascript
// ❌ login: db.users.find({user: req.body.user, pass: req.body.pass})
// Attacker sends JSON:
{"user":"admin","pass":{"$ne":null}}     // $ne null → matches → auth bypass
{"user":{"$regex":"^a"},"pass":{"$ne":1}} // enumerate chars
```
Also JS-context: `$where: "this.x == '" + input + "'"` → server-side JS injection.
**Fix:** cast inputs to expected types (a password must be a *string*, not an object), validate schemas, never pass raw request objects into queries, disable `$where`.

## The family (all same idea, know they exist)
| Injection | Sink | Marker |
|---|---|---|
| LDAP | directory query | `*)(uid=*` |
| XPath | XML query | `' or '1'='1` |
| Template | render engine | `{{7*7}}` → [[SSTI-Template-Injection]] |
| Header/CRLF | HTTP response | `%0d%0a` → response splitting |
| Log | log file | forged entries, or Log4Shell-style `${jndi:...}` |
| ORM | raw fragment | see [[Injection-SQLi]] |

## How to find (code review)
```bash
grep -rnE "shell=True|os\.system|exec\(|popen|child_process|Runtime.exec|\$where|\$ne" .
```
For each: does attacker data reach it, unneutralised? → finding.

## Practice + interview
- PortSwigger Academy → OS command injection + NoSQL injection labs.
- **Interview:** *How do you prevent command injection?* (Argument arrays, no shell; allowlist. Not metachar blocklisting.) *What is NoSQL injection if there's no SQL?* (Operator/type injection — send an object where a string was expected, `$ne`/`$regex`; cast + validate types.) *Why is `shell=True` dangerous?* (Invokes a shell that interprets metacharacters in user data.)

---
**Related:** [[Injection-SQLi]] · [[SSTI-Template-Injection]] · [[Insecure-Deserialization]]
