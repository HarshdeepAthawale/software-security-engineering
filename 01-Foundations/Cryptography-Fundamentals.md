---
tags: [foundations, crypto]
owasp: A04:2025
status: learning
---

# Cryptography Fundamentals (for engineers, not mathematicians)

> You will almost never break crypto math. You will constantly find crypto **misuse**. Focus there.

Maps to **A04:2025 — Cryptographic Failures**.

---

## The three things people confuse

| | Purpose | Reversible? | Key? | Example |
|---|---|---|---|---|
| **Encoding** | Data representation | Yes, by anyone | No | Base64, URL-encoding, hex |
| **Hashing** | Fingerprint / integrity | No (one-way) | No (unless HMAC) | SHA-256, bcrypt |
| **Encryption** | Confidentiality | Yes, with key | Yes | AES-GCM, RSA |

**Base64 is not encryption.** If you ever write "the data is protected because it's base64 encoded" in a report, you will be rejected instantly. Conversely, when *developers* do this, it's a real finding — sensitive data at rest with no confidentiality.

---

## Password storage

The only correct answer in 2026:

| Algorithm | Verdict | Notes |
|---|---|---|
| **Argon2id** | ✅ Best choice | Memory-hard, GPU/ASIC-resistant. Winner of the Password Hashing Competition |
| **scrypt** | ✅ Good | Memory-hard |
| **bcrypt** | ✅ Acceptable | Widely available. ⚠️ silently truncates input at 72 bytes |
| **PBKDF2** | ⚠️ Only if required by compliance (FIPS) | Not memory-hard; needs very high iteration counts |
| **SHA-256 / MD5 / SHA-1** | ❌ Broken for passwords | Too fast. Billions of guesses/sec on a GPU |
| Any of the above **unsalted** | ❌ | Rainbow tables |

```python
# ✅ Correct
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hash = ph.hash(password)          # salt is generated and embedded automatically
ph.verify(hash, candidate)        # raises on mismatch

# ❌ Wrong, and you will see this in real codebases
import hashlib
hash = hashlib.sha256(password.encode()).hexdigest()

# ❌ Also wrong — a global "pepper" used as the salt defeats per-user salting
hash = hashlib.sha256((SALT + password).encode()).hexdigest()
```

**The bcrypt 72-byte trap:** bcrypt ignores everything past 72 bytes. If you pre-hash with SHA-256 and hex-encode, you get 64 chars — fine. If you pre-hash and base64 *a longer digest*, or feed a long passphrase directly, distinct passwords can collide. Real CVEs exist for this (notably in Okta's implementation, 2024).

---

## Symmetric encryption

**Always use authenticated encryption (AEAD).** Encryption without integrity is a vulnerability, not a weaker form of security.

| Mode | Use it? | Why |
|---|---|---|
| **AES-GCM** | ✅ | AEAD. ⚠️ **Never reuse a nonce with the same key** — catastrophic, leaks the auth key |
| **ChaCha20-Poly1305** | ✅ | AEAD, fast without AES hardware |
| **XChaCha20-Poly1305** | ✅ | 192-bit nonce → random nonces are safe |
| AES-CBC + separate HMAC | ⚠️ | Only encrypt-then-MAC, done carefully |
| AES-CBC alone | ❌ | **Padding oracle attacks** |
| AES-ECB | ❌ | Identical plaintext blocks → identical ciphertext. The famous "ECB penguin" |

### The padding oracle, briefly
CBC decryption pads plaintext. If the app returns a distinguishable error for "bad padding" vs "bad data", an attacker decrypts the entire ciphertext byte by byte — without the key. ~256 requests per byte. This killed ASP.NET (CVE-2010-3332) and JSF among others.

**How to spot it in review:** CBC mode + any error path that differs between padding failure and downstream parse failure.

---

## Hashing & integrity

- `==` on secrets is a **timing side channel**. Use constant-time comparison:
  ```python
  import hmac
  hmac.compare_digest(provided_sig, expected_sig)   # ✅
  if provided_sig == expected_sig:                   # ❌ leaks via timing
  ```
- **HMAC ≠ hash(secret + message)**. The naive construction is vulnerable to **length extension** with Merkle–Damgård hashes (MD5, SHA-1, SHA-2). An attacker who knows `hash(secret + msg)` and `len(secret)` can compute `hash(secret + msg + padding + evil)` without knowing the secret. SHA-3 and BLAKE2 are immune. Just use HMAC.

---

## Randomness

```python
import random                    # ❌ Mersenne Twister — predictable after ~624 outputs
token = random.randint(0, 10**10)

import secrets                   # ✅ CSPRNG
token = secrets.token_urlsafe(32)
```

| Language | ❌ Insecure | ✅ Secure |
|---|---|---|
| Python | `random` | `secrets`, `os.urandom` |
| Java | `java.util.Random` | `java.security.SecureRandom` |
| JS (Node) | `Math.random()` | `crypto.randomBytes()` |
| JS (browser) | `Math.random()` | `crypto.getRandomValues()` |
| PHP | `rand()`, `mt_rand()` | `random_bytes()` |
| Go | `math/rand` | `crypto/rand` |

**Where it bites:** password reset tokens, session IDs, MFA codes, "unguessable" URLs. A predictable reset token is a full account takeover, and it's a genuinely common finding. Check the entropy *and* the source.

---

## TLS: what actually matters in review

The handshake in one paragraph: client and server agree on a cipher suite, the server proves its identity with a certificate chained to a trusted CA, they derive a shared symmetric key (ECDHE, giving **forward secrecy**), then everything after is symmetric AEAD.

Practical checklist:
- **TLS 1.3** preferred; 1.2 acceptable; 1.0/1.1 and SSLv3 disabled
- **Certificate validation actually enabled.** The most common real-world crypto bug in mobile/backend code:
  ```python
  requests.get(url, verify=False)          # ❌ disables all cert validation
  ```
  ```java
  // ❌ classic "trust everything" TrustManager — appears in production apps constantly
  new X509TrustManager(){ public void checkServerTrusted(...){ } }
  ```
- **HSTS** with preload, to stop the first-request downgrade
- **Certificate pinning** for mobile apps handling high-value operations (and know how to bypass it for testing — Frida/objection)

---

## Asymmetric crypto, quickly

- **RSA** — signing and encryption. Use OAEP for encryption, PSS for signatures. Textbook/PKCS#1v1.5 encryption is vulnerable (Bleichenbacher).
- **ECDSA / Ed25519** — signatures. **Ed25519 is the better default** (deterministic, no nonce-reuse footgun). ECDSA with a repeated `k` leaks the private key — this is how the PS3 was broken.
- **Post-quantum:** NIST standardised ML-KEM (Kyber) and ML-DSA (Dilithium) in 2024. Hybrid key exchange (X25519+ML-KEM) is now shipping by default in major browsers/TLS stacks. Know the term "harvest now, decrypt later" — it's why long-lived secrets need migration planning.

---

## The misuse checklist for code review

Scan for these in any codebase:

- [ ] Hardcoded keys/IVs (`key = "1234567890123456"`) → see [[Secrets-Management]]
- [ ] `ECB` anywhere
- [ ] Static or zero IV/nonce, or an IV derived from the plaintext
- [ ] Nonce reuse with AES-GCM
- [ ] `MD5` / `SHA1` for anything security-relevant
- [ ] Fast hashes for passwords
- [ ] `Math.random()` / `random` for tokens
- [ ] `verify=False`, `InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
- [ ] Custom crypto ("we wrote our own encryption") — always a finding
- [ ] Encryption without authentication
- [ ] `==` comparison on MACs/tokens
- [ ] Keys stored next to the data they encrypt

---

## Practice

1. Implement a padding oracle attack against a small CBC-mode service you write yourself. This is the single best crypto exercise; it makes "encryption without integrity" viscerally real.
2. Take two AES-GCM ciphertexts encrypted with the same key **and nonce** and XOR them. Observe what leaks.
3. Crack a list of unsalted SHA-256 password hashes with hashcat, then try the same list as Argon2id. Time both.
4. Do [Cryptopals](https://cryptopals.com) sets 1–2. Genuinely the best crypto training available.

---

## Interview questions

- *Difference between encoding, hashing, and encryption?* (Table above — the classic screening question.)
- *How would you store passwords?* (Argon2id, per-user salt handled by the library, plus rate limiting and breach-list checks. Bonus: mention pepper in an HSM/KMS.)
- *Why is AES-ECB bad?* (Deterministic per block → structure leaks. Show the penguin.)
- *What's wrong with `hash(secret + message)` as a MAC?* (Length extension. Use HMAC.)
- *An app encrypts a session cookie with AES-CBC and no MAC. What can you do?* (Padding oracle to decrypt; bit-flipping to tamper — flip a byte in block N to controllably corrupt block N+1's plaintext, e.g. flipping `admin=0` to `admin=1`.)

---

**Next:** [[Authentication-vs-Authorization]]
