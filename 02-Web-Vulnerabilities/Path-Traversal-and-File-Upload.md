---
tags: [vuln, web, path-traversal, upload]
owasp: A01:2025
difficulty: medium
status: learning
---

# Path Traversal & File Upload

Two closely related file-handling bug classes. Path traversal reads/writes files outside the intended directory; unsafe upload lets attacker-controlled files land where they can be executed or served.

## Path / Directory Traversal
User input reaches a filesystem path.
```python
# ❌
open(f"/var/www/files/{request.args['name']}")
# ?name=../../../../etc/passwd
```
**Bypasses** (see the bypass table in `security-arsenal`): `../`, `..\\`, URL-encoded `%2e%2e%2f`, double-encoded `%252e`, `....//` (filter strips one `../`), absolute paths, null byte `%00` (legacy), unicode.
**Fix:** don't put user input in paths. If you must: resolve to a canonical absolute path and assert it's still *inside* the intended base dir; use an allowlist of filenames / a mapping of IDs→paths.
```python
base = os.path.realpath("/var/www/files")
full = os.path.realpath(os.path.join(base, name))
if not full.startswith(base + os.sep): abort(403)   # ✅ canonicalize then contain
```

## Unrestricted / Unsafe File Upload
| Risk | How | Fix |
|---|---|---|
| **RCE via webshell** | Upload `shell.php` into a web-served, executable dir | Store outside webroot; don't execute upload dirs; randomize names; strip extensions |
| Content-type spoofing | `Content-Type: image/png` on a PHP file | Validate by content (magic bytes), not the client-supplied type |
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.phtml`, trailing dot/space, null byte | Allowlist extensions; re-encode images; reject double extensions |
| Path traversal in filename | `../../shell.php` as the name | Sanitize/replace the filename entirely |
| SVG/XML upload | `<svg>` with script → stored XSS; or XXE | Sanitize SVG, serve `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` |
| Pixel-flood / zip-bomb | Resource exhaustion | Size limits, decompression limits |
| Overwrite | Upload named `config.php` | Never let user control the stored path/name |

**The gold standard:** store uploads outside the webroot, under a random name, serve them through a handler that sets `Content-Disposition: attachment` + `nosniff`, validate content by magic bytes + re-encode images, and never place them in a directory the server will execute.

## How to find
- Any endpoint taking a filename/path param → try `../`.
- Any upload → try the extension/content-type bypasses; check where the file lands and whether it's reachable/executable.
```bash
grep -rnE "open\(|readFile|sendFile|include\(|require\(|os.path.join\(.*request" .
```

## Practice + interview
- PortSwigger Academy → **path traversal** and **file upload** labs (all bypasses).
- **Interview:** *How do you safely handle file paths from users?* (Canonicalize then contain within base; better, map IDs to paths.) *How do you make file upload safe?* (Outside webroot, random name, no exec, content-based validation + re-encode, attachment disposition + nosniff.) *Why isn't checking `Content-Type` enough?* (Client controls it; validate magic bytes.)

---
**Related:** [[SSRF-Server-Side-Request-Forgery]] · [[XXE-and-XML-Attacks]] · [[XSS-Cross-Site-Scripting]] · [[Broken-Access-Control-IDOR]]
