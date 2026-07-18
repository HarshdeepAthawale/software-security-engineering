---
tags: [vuln, web, a08, deserialization]
owasp: A08:2025
difficulty: high
status: learning
---

# Insecure Deserialization

> **A08:2025 — Software and Data Integrity Failures.** Deserializing untrusted data can instantiate arbitrary objects and run code *during reconstruction* → frequently **RCE**. It's among the scariest common web bugs because a single vulnerable sink can hand over the entire server, often pre-authentication.

---

## 1. Serialization vs the danger

**Serialization** turns an in-memory object into a byte stream (to store/transmit); **deserialization** rebuilds it. The danger arises when the format encodes **object *types* and *behaviour*, not just data** — then an attacker crafts a stream that, on deserialization, constructs objects whose lifecycle methods (constructors, `__wakeup`, `readObject`, `__destruct`, finalizers) execute attacker-chosen logic. Chaining such classes into an exploit is a **gadget chain**.

Data-only formats (plain JSON, plain XML) are **generally safe** — until a library adds *type embedding* (polymorphic deserialization), which reintroduces the whole problem.

---

## 2. The dangerous sinks by language

```python
# ❌ Python — pickle executes arbitrary code by design
import pickle
obj = pickle.loads(untrusted_bytes)          # game over
data = yaml.load(untrusted)                   # ❌ use yaml.safe_load
```
```java
// ❌ Java — the classic RCE surface (ysoserial gadget chains)
ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
Object o = in.readObject();
```
```php
// ❌ PHP — POP chains via magic methods (__wakeup, __destruct)
$obj = unserialize($_COOKIE['data']);
```
```ruby
# ❌ Ruby
Marshal.load(untrusted)
YAML.load(untrusted)                          # ❌ use YAML.safe_load
```
```csharp
// ❌ .NET — BinaryFormatter / type-embedded JSON
new BinaryFormatter().Deserialize(stream);
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All    // ❌ reopens RCE via $type
});
```
```java
// ❌ Java JSON with polymorphic typing
@JsonTypeInfo(use = Id.CLASS)   // Jackson default-typing → gadget RCE
```

### Recognising serialized blobs (in cookies, params, hidden fields, caches, queues)
| Prefix | Format |
|---|---|
| `rO0` (base64) / `\xac\xed\x00\x05` | Java serialization |
| `gASV`, `gAJ`, `\x80\x04` | Python pickle |
| `O:8:"User":...` | PHP serialize |
| `BAh` (base64) | Ruby Marshal |
| `AAEAAAD/////` | .NET BinaryFormatter |
| `{"$type": ...}` | .NET/Jackson polymorphic JSON |

---

## 3. Exploitation — gadget chains

You don't need the app's own classes. You abuse **gadgets** — classes already on the classpath/in installed libraries — whose combined lifecycle behaviour reaches a dangerous sink (`Runtime.exec`, `system`, a template eval, a JNDI lookup). Tools build these payloads:

| Language | Tool | Notes |
|---|---|---|
| Java | **ysoserial** | `java -jar ysoserial.jar CommonsCollections6 'id' | base64` |
| .NET | **ysoserial.net** | `TypeConfuseDelegate`, `ObjectDataProvider` gadgets |
| PHP | **phpggc** | `phpggc Monolog/RCE1 system id` |
| Python | hand-crafted | `__reduce__` returns `(os.system, ('id',))` |

Python pickle RCE minimal example:
```python
import pickle, os, base64
class E:
    def __reduce__(self): return (os.system, ('id',))
payload = base64.b64encode(pickle.dumps(E()))   # server that unpickles this runs `id`
```

**PHP POP chain** idea: find a class with a useful `__destruct`/`__wakeup`, whose properties you control via the serialized string, that calls into a sink — set those property values in the crafted `O:...` string.

---

## 4. How to find it (review + black-box)
- Grep the sinks in §2; trace whether attacker data reaches them (cookies are the #1 spot, then hidden fields, API bodies, message queues, cached objects, uploaded files).
- In black-box: spot serialized blobs by prefix (§2), then tamper — flip a field, observe error behaviour, then try a tool-generated gadget for the detected stack.
- Look for **polymorphic JSON** config (`TypeNameHandling`, Jackson default typing) — a subtle reintroduction in "safe" JSON apps.
```bash
grep -rnE "pickle.loads|yaml.load\(|Marshal.load|readObject|unserialize\(|BinaryFormatter|TypeNameHandling|enableDefaultTyping" .
```

## 5. The fix
1. **Don't deserialize untrusted data.** The only complete fix. Redesign to avoid it where possible.
2. Use **data-only formats** (plain JSON) parsed into **known, explicit types** with schema validation — never "deserialize into whatever type the data says."
3. If native serialization is unavoidable:
   - **Integrity-protect the blob** — sign it (HMAC, see [[Cryptography-Fundamentals]]) so attackers can't forge/modify it. (Protects integrity, not confidentiality; combine with the below.)
   - **Allowlist permitted classes** (Java `ObjectInputFilter`/`ValidatingObjectInputStream`, PHP `unserialize($x, ['allowed_classes'=>[...]])`).
   - Use `yaml.safe_load` / `YAML.safe_load`; never native `pickle`/`Marshal`/`BinaryFormatter` on untrusted input (`BinaryFormatter` is deprecated in modern .NET for this reason).
   - **Disable polymorphic typing** in JSON libraries.
4. Least-privilege the process and network egress to blunt post-exploitation ([[Secure-Design-Principles]]).

## 6. Real-world cases
- **Apache Commons-Collections (2015)** — the gadget chain that made Java deserialization RCE ubiquitous; a decade of enterprise RCEs (WebLogic, JBoss, Jenkins, WebSphere) traced to `readObject` on untrusted input.
- **Oracle WebLogic (CVE-2015-4852, CVE-2017-10271, CVE-2019-2725, and more)** — repeated deserialization RCEs, heavily mass-exploited.
- **Apache Struts (CVE-2017-5638)** — expression/deserialization-class RCE behind the **Equifax breach** (~147M people).
- **Log4Shell (CVE-2021-44228)** — JNDI lookup via logged strings; an integrity/deserialization-adjacent RCE that reshaped the industry.
- **.NET `ViewState`** without MAC — deserialization RCE via forged ViewState.

## 7. Practice + interview questions

### Practice
- **PortSwigger Academy → Insecure deserialization** — all labs (PHP object injection first, then building/using a gadget chain, then a documented gadget with a tool).
- Reproduce a Python pickle `__reduce__` RCE against a toy service you write. Then reproduce a Java `readObject` RCE with ysoserial against a vulnerable demo.

### Interview questions
- *Why is deserializing untrusted data dangerous?* (It reconstructs typed objects and runs lifecycle code → gadget chains → RCE, often pre-auth.)
- *Is JSON safe from this?* (Data-only JSON parsed into known types, yes — unless polymorphic/type-embedding is enabled, e.g. Jackson default typing, `.NET TypeNameHandling`.)
- *What's a gadget chain?* (A sequence of existing library classes whose deserialization lifecycle reaches a dangerous sink; you don't need the app's own classes.)
- *How do you fix it if you must deserialize?* (Prefer data-only + schema; else sign the blob, allowlist classes, use safe loaders, disable polymorphic typing.)
- *You see a base64 cookie starting `rO0`. What is it and what do you do?* (Java serialized object → try ysoserial gadget for the stack's libraries → potential RCE.)

---

**Related:** [[SSTI-Template-Injection]] · [[Injection-Command-and-NoSQL]] · [[CI-CD-and-Software-Supply-Chain]] (A08 sibling: integrity) · [[Cryptography-Fundamentals]]
