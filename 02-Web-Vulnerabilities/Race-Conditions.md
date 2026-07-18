---
tags: [vuln, web, race-condition, business-logic]
difficulty: high
status: learning
---

# Race Conditions

> A **window between a check and the action that depends on it (TOCTOU — time-of-check to time-of-use)** where concurrent requests interleave, so a limit meant to hold "once" holds N times. Classic impacts: redeem a coupon many times, withdraw more than your balance, bypass a one-per-user limit, brute-force past an attempt counter.

---

## 1. The mechanism

```
Time  Request A                 Request B
 t0   read balance = $100
 t1                             read balance = $100     ← both pass the check
 t2   balance >= $100 ✓
 t3                             balance >= $100 ✓
 t4   withdraw $100 → $0
 t5                             withdraw $100 → -$100    ← limit bypassed
```

Root cause: the **check** (`balance >= amount`) and the **state mutation** (`balance -= amount`) are **not atomic**, and the application assumes requests are processed one-at-a-time. Under concurrency, multiple requests slip between the check and the update while the guarded value is still "good."

**"Limit overrun"** is the general shape: any per-user/per-account/per-time limit that's enforced as *read → decide → write* in application code is a candidate.

---

## 2. Where they hide

| Category | Example |
|---|---|
| **Money / balance** | Withdraw, transfer, spend store credit, convert points |
| **Redeem-once** | Coupon, gift card, referral bonus, one-time discount |
| **Claim-once** | Signup bonus, vote, like, follow, "1 per customer" purchase |
| **Rate/attempt limits** | Send many login/OTP attempts in parallel to beat the counter → [[MFA-and-Account-Recovery-Bypass]] |
| **Uniqueness** | Register two accounts with the same username/email in the gap before the unique check commits |
| **State transitions** | Approve + cancel simultaneously; upgrade role during a permission check |
| **Multi-step / partial-construction** | Act on an object between creation and its authz being set (a "sub-state" race) |

---

## 3. Exploitation — the single-packet attack

The challenge is delivering requests *simultaneously enough* that they land in the same tiny window despite network jitter.

- **Burp Repeater → "Send group in parallel" (single-packet attack)** — the modern default. It puts the last byte of ~20–30 requests into a **single TCP packet**, so the server receives them essentially at once, eliminating network-jitter as a variable. This is **James Kettle's single-packet attack (2023)** and it made previously-unexploitable, sub-millisecond windows reliably hittable over the internet.
- **Turbo Intruder** with the `race-single-packet-attack` template for scripted/high-volume races.
- Older technique (still useful on HTTP/1): the "last-byte sync" — send all requests withholding the final byte, then release all final bytes together.

Know the term **single-packet attack** by name — it's the thing interviewers and modern writeups reference.

---

## 4. Detecting races in review / black-box
- **Review:** look for `read → check → write` on a shared resource without a transaction/lock/atomic op or unique constraint. Grep for balance/credit/coupon logic that does a `SELECT` then a separate `UPDATE`.
- **Black-box:** any endpoint enforcing a "once"/limit — fire it 20–50× in parallel and check whether the effect exceeded the limit (two redemptions, negative balance, two accounts). Compare parallel vs sequential behaviour.

## 5. The fix — enforce atomicity at the data layer (never in app logic)

```sql
-- ✅ Atomic conditional update: the check and the decrement are ONE statement.
-- If two run concurrently, the DB serialises them; the second sees the new balance.
UPDATE accounts
SET balance = balance - 100
WHERE id = :id AND balance >= 100;
-- affected-rows = 0  → insufficient funds (the guard held under concurrency)
```

Techniques, strongest-first:
- **Atomic operations** — a single conditional `UPDATE`, atomic counters, `INSERT ... ON CONFLICT`.
- **Unique constraints** — make "claim once" structurally impossible to violate (DB rejects the second insert). The cleanest fix for redeem/claim races.
- **Row/advisory locks & transactions** — `SELECT ... FOR UPDATE` inside a transaction with appropriate isolation (`SERIALIZABLE` where needed) so concurrent readers block.
- **Idempotency keys** — for money/create operations, a repeated request carrying the same key is a no-op; the *first* wins, duplicates are ignored.
- **Optimistic concurrency** — a `version` column; the update fails if the version changed.

Do **not** rely on application-level `if balance >= amount:` followed by a separate write — that *is* the bug.

## 6. Real-world cases
- **PortSwigger / James Kettle "Smashing the state machine" (2023)** — introduced the single-packet attack and multi-step "sub-state" races; the definitive modern reference, with real-target examples (limit overruns, MFA bypasses, coupon abuse).
- **Bug bounty staples** — gift-card/coupon multi-redemption, converting store credit multiple times, following past a limit, and bypassing OTP/2FA attempt limits via parallel submission appear constantly in disclosed reports.
- **Exchange/fintech incidents** — double-withdrawal races have caused real financial loss on crypto platforms.

## 7. Practice + interview questions

### Practice
- **PortSwigger Academy → Race conditions** — all labs (they teach and use the single-packet attack: limit overrun, multi-endpoint, single-endpoint, partial-construction/sub-state, and race-based rate-limit bypass). This is the best race-condition training available.
- Build an endpoint with `if balance >= amount: balance -= amount` (separate read/write), exploit it with Burp parallel send, then fix it with the atomic `UPDATE` and confirm the race dies.

### Interview questions
- *What is a TOCTOU race, with a web example?* (Gap between check and use; e.g. two parallel withdrawals both pass the balance check before either debits → double-spend.)
- *How do you fix a race condition properly?* (Atomicity at the data layer — conditional `UPDATE`, unique constraints, `SELECT FOR UPDATE`/serializable transactions, idempotency keys. Not application-level checks.)
- *What's the single-packet attack and why does it matter?* (Delivers many requests' final bytes in one TCP packet, removing network jitter so tiny windows are reliably hit over the internet — made race exploitation practical.)
- *You suspect a coupon can be redeemed twice — how do you test and then prevent it?* (Fire redemptions in parallel; prevent with a unique constraint on (user, coupon) or an atomic decrement of remaining uses.)
- *Why isn't `if not used: mark_used()` in code enough?* (The check and the mark aren't atomic; concurrent requests both see "not used." Enforce with a DB constraint/atomic update.)

---

**Related:** [[Business-Logic-Flaws]] · [[MFA-and-Account-Recovery-Bypass]] · [[Broken-Access-Control-IDOR]]
