---
tags: [vuln, web, a05, injection]
owasp: A05:2025
difficulty: medium
status: learning
---

# SQL Injection

> **A05:2025 — Injection.** The oldest trick that still works. The mechanism — *untrusted data crosses from data context into code context* — is the same idea behind [[XSS-Cross-Site-Scripting]], [[Injection-Command-and-NoSQL]], [[SSTI-Template-Injection]], and [[XXE-and-XML-Attacks]]. Learn to *see the boundary* and you understand every injection class at once.

---

## 1. What it actually is

User input is concatenated into a SQL query string, so the input can change the query's **structure**, not just its data.

```sql
-- Intended
SELECT * FROM users WHERE username = 'alice' AND password = 'secret'

-- Input: username = admin'--
SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
--                                          ^^ rest commented out → auth bypass
```

---

## 2. Root cause

**Mixing code and data in the same string.** The database has no way to know which characters the developer intended as SQL syntax versus which came from the user. Parameterized queries fix this by sending code and data over *separate channels* — the query structure is compiled first, then data is bound in and can never be re-interpreted as syntax.

---

## 3. Vulnerable code

```python
# ❌ String formatting — the root sin, in every language
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
cur.execute("... WHERE name = '" + name + "'")
```
```javascript
// ❌ Node
db.query(`SELECT * FROM products WHERE cat = '${category}'`);
```
```java
// ❌ Java
stmt.execute("SELECT * FROM t WHERE id = " + request.getParameter("id"));
```

**The subtle one — ORMs are not automatically safe:**
```python
# ❌ raw fragment inside an ORM
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.extra(where=[f"name = '{name}'"])           # Django .extra is dangerous
```
```javascript
// ❌ Sequelize with interpolation
sequelize.query(`SELECT * FROM u WHERE id = ${id}`);
```
ORMs are safe **only** when you use their parameter binding. The moment you drop to raw SQL with interpolation, you're back to square one.

---

## 4. How to find it

### Detection
| Type | Test | Signal |
|---|---|---|
| **Error-based** | Inject `'` | DB error in response → injectable, and the DB tells you its type |
| **Boolean-blind** | `' AND 1=1--` vs `' AND 1=2--` | Page differs between true/false |
| **Time-blind** | `'; SELECT pg_sleep(5)--` | Response delayed → injectable even with no output |
| **UNION** | `' UNION SELECT NULL,NULL--` | Adjust NULLs until no error → you can pull arbitrary columns |
| **Out-of-band** | trigger a DNS lookup to your server | Works when there's no in-band feedback at all |

### Where to inject (not just form fields)
- URL/query params, POST body, JSON values
- **HTTP headers**: `User-Agent`, `Referer`, `X-Forwarded-For` — often logged straight into SQL
- Cookies
- `ORDER BY` / `LIMIT` clauses — **cannot be parameterized**, so they're a frequent blind spot (see fix section)
- Second-order: input stored now, concatenated into a query later (a username saved at registration, used unsanitized in an admin report)

### Code review greps
```bash
grep -rnE "execute\(.*(%|\+|f['\"]|\$\{|format\()" .
grep -rn "\.raw(\|\.extra(\|sequelize.query(" .
```
For each: does user data reach the string, or is it bound as a parameter?

---

## 5. Exploitation

```sql
-- Auth bypass
' OR '1'='1'--
admin'--

-- Enumerate the schema (after finding UNION column count)
' UNION SELECT table_name, NULL FROM information_schema.tables--
' UNION SELECT username, password FROM users--

-- DB fingerprint one-liners
' AND 1=CONVERT(int,@@version)--    -- MSSQL error leaks version
' AND extractvalue(1,version())--   -- MySQL
'; SELECT version()--               -- Postgres
```

**Escalation beyond data theft:**
- Read files: `... UNION SELECT LOAD_FILE('/etc/passwd')` (MySQL, with FILE priv)
- Write a webshell: `... INTO OUTFILE '/var/www/shell.php'` → RCE
- MSSQL `xp_cmdshell` → OS command execution → RCE
- Postgres `COPY ... FROM PROGRAM` → RCE
- Pivot to internal network via stacked queries

**Use `sqlmap` to confirm and exploit** — but *only after you understand it manually*. Interviewers ask you to do it by hand; "I run sqlmap" is a junior answer.
```bash
sqlmap -r request.txt --batch --dbs        # from a saved Burp request
sqlmap -r request.txt --dump -T users
```

---

## 6. The fix

**Parameterized queries / prepared statements. Every time. No exceptions.**

```python
# ✅ Python
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
```javascript
// ✅ Node
db.query("SELECT * FROM products WHERE cat = ?", [category]);
```
```java
// ✅ Java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, id);
```

**The parts you cannot parameterize** — table/column names, `ORDER BY`, `ASC/DESC`, `LIMIT` direction — must be validated against an **allowlist**, never concatenated:
```python
SORT_COLS = {"name", "created_at", "price"}   # allowlist
col = req.args.get("sort")
if col not in SORT_COLS:
    abort(400)
query = f"SELECT * FROM products ORDER BY {col}"   # safe: col ∈ fixed set
```

Defence-in-depth (never a substitute for parameterization):
- Least-privilege DB user (no FILE, no DDL, no `xp_cmdshell`)
- ORM with bound params as the default path
- WAF as a speed bump, not a fix — every WAF is bypassable
- **Input validation is not a fix.** Blocklisting `'` breaks legitimate names (O'Brien) and is bypassable a dozen ways. Parameterize instead.

---

## 7. Real-world cases

- **Heartland Payment Systems (2008)** — SQLi entry point → ~130M card records. One of the largest breaches ever, from a single injectable form.
- **Sony Pictures (2011, LulzSec)** — "one SQLi" reportedly dumped a million accounts stored in plaintext.
- **TalkTalk (2015)** — SQLi on a legacy page, 157k customers, £400k ICO fine.
- **MOVEit Transfer (CVE-2023-34362)** — SQLi in a widely-used file transfer product, mass-exploited by Cl0p, thousands of orgs downstream. A modern reminder that SQLi is far from dead.
- **Fortinet, Ivanti, various 2024–2025 appliance CVEs** — SQLi remains a top initial-access vector in enterprise gear.

---

## 8. Practice + interview questions

### Practice
1. **PortSwigger Academy → SQL injection** — all labs, especially the blind and time-based ones (blind is what real targets look like).
2. Build the vulnerable Flask login, bypass it with `admin'--`, then fix it with a prepared statement and confirm the payload dies.
3. Exploit a blind boolean injection *by hand* to extract a password character by character. Then reproduce with sqlmap and compare.
4. Do an `ORDER BY` injection — it teaches you why parameterization has limits and allowlists exist.

### Interview questions
- *Explain SQLi to a developer and how to fix it permanently.* (Code/data mixing → parameterized queries send them on separate channels. Mention the ORDER BY allowlist caveat to show depth.)
- *Is input validation enough to stop SQLi?* (No — bypassable, breaks valid input, wrong layer. Parameterize.)
- *An ORM is used everywhere. Are you safe from SQLi?* (Only where binding is used. Raw fragments / `.extra` / `.raw` / string interpolation re-open it.)
- *You've confirmed blind time-based SQLi. Walk me through escalating to RCE.* (Fingerprint DB → check DB user privileges → file write to webroot / `xp_cmdshell` / `COPY FROM PROGRAM` depending on engine → shell.)
- *Why can't you parameterize a table name?* (Prepared statements bind *values* into a pre-compiled plan; identifiers change the plan itself, so they must be fixed or allowlisted.)

---

**Related:** [[Injection-Command-and-NoSQL]] · [[XSS-Cross-Site-Scripting]] · [[SSTI-Template-Injection]] — same root cause, different sink.
