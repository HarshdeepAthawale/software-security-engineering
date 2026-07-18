---
tags: [vuln, web, cache]
difficulty: high
status: learning
---

# Web Cache Poisoning & Deception

> Caches (CDN, reverse proxy) serve one stored response to many users. If an attacker can get a *malicious* response cached under a key that victims will request, one request poisons everyone. Related to the length/parsing-mismatch theme in [[HTTP-Request-Smuggling]] and header trust in [[HTTP-Deep-Dive]].

## Cache poisoning — the mechanism
1. The cache **key** = the parts of the request it uses to decide "same response" (usually method + host + path, sometimes query).
2. **Unkeyed inputs** — headers the app *reflects into the response* but the cache *ignores* when keying (e.g. `X-Forwarded-Host`, `X-Forwarded-Scheme`, custom headers).
3. Attacker sends a request with a malicious unkeyed header that gets reflected (e.g. into a script `src`, a redirect, or a link); the poisoned response is cached; every subsequent victim on that key gets it.

```
GET /  H: X-Forwarded-Host: evil.com
→ app reflects it:  <script src="//evil.com/x.js">
→ cached → served to all users → mass XSS
```

## Finding it
- Identify **unkeyed inputs** that reach the response (Burp **Param Miner** automates header/param discovery).
- Confirm the response is cacheable (`Cache-Control`, `Age`, `X-Cache: hit` headers).
- Verify the poisoned response persists for other cache keys.

## Cache *deception* (the sibling)
Trick the cache into storing a *sensitive authenticated* response under a static-looking URL, then read it unauthenticated:
```
/account/profile/nonexistent.css
→ app returns the profile (ignores the fake extension), cache stores it as "static"
→ attacker fetches the .css URL → reads victim's cached private data
```

## The fix
- Include all response-affecting inputs in the **cache key**, or don't reflect unkeyed inputs at all.
- **Don't cache authenticated/sensitive responses** — `Cache-Control: no-store, private` on them.
- Normalize/strip untrusted headers (`X-Forwarded-*`) at the edge.
- Cache by the *normalized* path; don't let extension tricks reclassify dynamic content as static.
- Remember `Vary: Origin` for CORS (see [[Browser-Security-Model]]).

## Interview
- *What is web cache poisoning?* (Malicious response cached via an unkeyed-but-reflected input → served to all users.) *Cache deception?* (Sensitive response cached under a static-looking URL → read by others.) *Fix?* (Key on all response-affecting inputs, never cache authenticated responses, strip untrusted headers.)

---
**Related:** [[HTTP-Request-Smuggling]] · [[HTTP-Deep-Dive]] · [[Browser-Security-Model]]
