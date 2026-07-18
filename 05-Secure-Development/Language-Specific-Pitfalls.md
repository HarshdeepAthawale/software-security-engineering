---
tags: [secure-dev, code-review]
status: learning
---

# Language-Specific Pitfalls

> Each ecosystem has footguns that create bugs. Knowing them makes [[Secure-Code-Review-Methodology]] far faster — you grep straight for the language's known traps. Your `bug-bounty` skill has language-specific grep patterns; this is the mental index.

## JavaScript / Node / TypeScript
- **Prototype pollution** — `obj[userKey] = userVal` with `__proto__`/`constructor.prototype` → pollute Object prototype → DoS, authz bypass, sometimes RCE. Grep: recursive merge/`Object.assign` on user input, `lodash.merge`.
- `child_process.exec` (shell) vs `execFile` (no shell) → command injection.
- `eval`, `Function()`, `vm` with user input.
- `dangerouslySetInnerHTML`, `v-html` → XSS.
- Type coercion: `==` weirdness, `[]==false`.
- npm: install scripts, typosquatting → [[CI-CD-and-Software-Supply-Chain]].

## Python
- `pickle.loads`, `yaml.load` (use `safe_load`) → [[Insecure-Deserialization]].
- `subprocess(..., shell=True)`, `os.system` → command injection.
- `eval`/`exec`/`__import__` on input.
- `str.format`/f-strings into SQL → [[Injection-SQLi]]; format-string info leak via `{0.__globals__}`.
- Jinja2 `render_template_string` → [[SSTI-Template-Injection]].
- `assert` for security checks (stripped with `-O`).
- Mutable default args; `requests(..., verify=False)`.

## Java
- `ObjectInputStream.readObject` → deserialization RCE (ysoserial).
- XML parsers default-unsafe → [[XXE-and-XML-Attacks]].
- `Runtime.exec` (careful: it doesn't use a shell, but string-splitting surprises).
- Expression Language / SpEL injection (`#{...}`), Log4Shell (`${jndi:...}`).
- Reflection abuse; trusting `equals` for auth tokens (timing).

## PHP
- `unserialize()` → POP chains; `include`/`require` with user input → LFI/RFI/[[Path-Traversal-and-File-Upload]].
- **Type juggling** — `==` : `"0e123" == "0e456"` (both "0"), `strcmp(array)` returns null → auth bypass. Use `===`.
- `extract()`, `$$var` variable variables → mass assignment.
- `eval`, `assert`, `preg_replace` with `/e`.

## Go
- `text/template` vs `html/template` — using `text/template` for HTML = XSS (no auto-escape). `template.HTML(userInput)` bypasses escaping.
- `exec.Command` with a shell wrapper; SQL string building.
- Ignored errors (`_ =`) hiding security failures; nil-pointer paths.

## Ruby
- `YAML.load` (use `safe_load`), `Marshal.load` → deserialization.
- `eval`/`send`/`constantize` with user input; mass assignment (strong params).
- `%x[]`/backticks/`system` with interpolation → command injection.

## Rust (yes, memory-safe ≠ bug-free)
- `unsafe` blocks; `.unwrap()`/`.expect()` panics → DoS.
- Integer overflow in release builds; `unsafe` FFI boundaries; logic bugs and injection still fully possible.

## Interview
- *Name a footgun in \[your main language\] and how you'd catch it in review.* Be ready for at least the language on your resume. *What's prototype pollution?* (Polluting `Object.prototype` via `__proto__` in a merge → affects all objects → authz bypass/DoS/RCE.) *PHP type juggling?* (`==` loose comparison across types → auth bypass; use `===`.)

---
**Related:** [[Secure-Code-Review-Methodology]] · `bug-bounty` skill (language grep) · [[Insecure-Deserialization]]
