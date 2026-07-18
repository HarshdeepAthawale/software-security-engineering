---
tags: [vuln, web, business-logic, a06]
owasp: A06:2025
difficulty: medium
status: learning
---

# Business Logic Flaws

> Bugs where **no rule of HTTP or code is broken** — the application does exactly what it was coded to do, but the *logic* lets an attacker achieve something they shouldn't. Scanners can't find these; only a human who understands the app's *intent* can. This makes them high-value and interview-favourite. Related to **A06:2025 — Insecure Design**.

## The nature
There's no injection, no missing escape. The developer's *assumptions* are wrong: they assumed a value would be positive, a step would happen in order, a client-side check couldn't be skipped.

## Common patterns
| Pattern | Example |
|---|---|
| **Negative / overflow values** | Buy `-1` items → refund; transfer negative → steal |
| **Price/parameter tampering** | `price` sent client-side; change `9.99`→`0.01`; apply a $ discount larger than the total |
| **Skipping steps** | Jump straight to the "payment confirmed" endpoint without paying |
| **Reusing one-time things** | Replay a used coupon/token; re-submit a signed request |
| **Quantity/limit bypass** | "Max 1 per customer" enforced only in the UI |
| **Workflow order** | Cancel after ship; refund after delivery; approve your own request |
| **Trusting client-side state** | Role/price/discount decided by a hidden field or JS |
| **Currency/rounding** | Exploit rounding across conversions; tiny fractions summed |
| **Excessive trust in "internal" flows** | An endpoint assumed unreachable but directly callable |

## How to find (this is a mindset, not a scan)
1. **Understand the intended flow fully** — what is the app *trying* to enforce, and what does it *assume*?
2. For every assumption, ask "what if I violate it?" — negative numbers, out of order, skipped, replayed, in parallel ([[Race-Conditions]]).
3. Manipulate every client-controlled value that *shouldn't* be trusted (price, quantity, role, status, IDs).
4. Try each step of a multi-step flow **out of sequence** and in isolation.

## The fix
- **Enforce every business rule server-side** — the client is untrusted, always.
- Validate ranges/signs/types (quantity > 0, price is server-derived not client-sent).
- Enforce workflow state machines server-side (you can't reach "shipped" without "paid").
- Make one-time actions one-time (idempotency, unique constraints — see [[Race-Conditions]]).
- Re-derive security-relevant values (price, discount, role) on the server; never accept them from the client.

## Practice + interview
- PortSwigger Academy → **Business logic vulnerabilities** labs (a whole excellent set).
- **Interview:** *What's a business logic flaw and why can't scanners find them?* (Logic/intent violation, no technical rule broken; tools don't know your rules.) *Give an example.* (Negative quantity refund; client-side price; skipping the payment step.) *How do you prevent them?* (Server-side enforcement of all rules, validate ranges, server-derived prices, state machines.)

---
**Related:** [[Race-Conditions]] · [[Broken-Access-Control-IDOR]] · [[Threat-Modeling]] · [[API-Security-OWASP-API-Top-10]]
