# AGENTS.md

Guidance for working in this repository.

**This file is loaded into every session, so it stays small on purpose.** It holds only the rules you
need *before* you know what you are about to touch. Three-file contract:

| File | Holds | Rule |
| --- | --- | --- |
| `AGENTS.md` (this file) | Always-on rules and a routing table | Add a line here only if breaking the rule causes **silent** damage AND the code you would be editing gives you no warning. |
| `docs/<topic>.md` | The current-state contract for one subsystem | Everything else. See [docs/README.md](docs/README.md). |
| `changelog.md` | The dated changelog (history, rationale, war stories) | What changed and why. |

If you are about to append a paragraph to this file, you are almost certainly in the wrong file.

## What this is

**OriginGuard** is a standalone ColdBox module that provides modern, stateless CSRF protection by validating browser-controlled request headers such as Sec-Fetch-Site, Origin, and Referer. It replaces traditional session-based CSRF tokens, hidden form fields, and client-side token refresh logic with a reusable origin-verification service that can protect unsafe HTTP requests, support explicitly trusted cross-origin callers, and account for trusted reverse proxies while remaining compatible with non-browser and automated clients.

## Engine support

Lucee 5+, Adobe ColdFusion 2023+, BoxLang 1+. Code must run on all three. See **Cross-engine** below.

This module ships only CFML source (no native `.bx` code), so BoxLang is supported through the
CFML-compatibility layer: the `boxlang-cfml` server boots BoxLang and installs `bx-compat-cfml`.
There is no native-BoxLang engine here (`start:boxlang-cfml`, not `start:boxlang`).

## Directory layout

| Path | Purpose |
| --- | --- |
| `ModuleConfig.cfc` | Settings defaults and interceptor registration. Read this first. |
| `models/OriginVerifier.cfc` | The decision engine. Pure and stateless; all security logic lives here. |
| `interceptors/OriginFirewall.cfc` | Turnkey enforcement (`preProcess`). Protects every unsafe event by default; scoped with `secureList` / `whiteList` regex patterns. |
| `interceptors/MethodGuard.cfc` | **Temporary shim** for a ColdBox bug ([COLDBOX-1406](https://ortussolutions.atlassian.net/browse/COLDBOX-1406)): strips a forged `_method` off a safe verb. Reads no settings and cannot be switched off. Delete the whole file when ColdBox ships the fix; its header says how. |
| `handlers/Errors.cfc` | The default 403 denial renderer. No views, no layouts. |
| `test-harness/` | A full ColdBox app whose only job is to run the module under test. CFML specs live here. `modules_app/guinea/` is the fixture module the integration specs protect. |
| `build/` | `Build.cfc`, which produces the distributable zip. |
| `docs/` | Subsystem reference docs. Dev-only, excluded from the build. |

## Cross-engine (Lucee 5 / ACF 2023 / BoxLang)

- **Never name a caller local the same as the callee's parameter** when passing it positionally. Lucee
    mis-resolves the argument and throws `UDFCasterException`, or worse, passes null.
- **Never name a method after a CFML built-in function.** An unscoped call inside the component
    resolves to the BIF on Lucee, silently changing semantics. This repo hit it twice: a method named
    `evaluate()` invoked the dynamic-evaluation BIF, and `listContains()` would have swapped exact-item
    matching for the BIF's substring matching (hence `evaluateHeaders()` and `isInList()`).
- **`isValid( "numeric", v )` is lenient on Lucee** (it accepts `"1.2.3"`). Use `isNumeric()` when the
    value feeds a numeric column.
- Prefer `keyExists()` over the Elvis operator `?:`.
- Adobe passes arrays by value.
- **Never name a function-local after a built-in scope** (`session`, `application`, `request`,
    `url`, `form`, `cookie`). `var session = {}` shadows the scope on ACF but NOT on Lucee, where
    every read/write silently hits the real session scope
- Write struct keys/assertions as strings, never bare numerics (Bad: `info[ "7" ]`, `toHaveKey( "7" )`)

## Data, files and settings

- **Struct keys the client reads must be assigned with QUOTED keys** (`row[ "iconClass" ] = ...`).
    Unquoted dot notation stores the key UPPERCASED, so `serializeJSON` emits `"ICONCLASS"` and the JS
    reads `undefined`.

## Common commands

Everything CFML-side runs through [CommandBox](https://commandbox.ortusbooks.com/) (`box`). The embedded
server's webroot is `test-harness/`, and `server.json` aliases the module paths to the repo root, so the
harness loads the module under development without a separate install.

```bash
box run-script install:dependencies   # module + test-harness dependencies

box run-script start:lucee5           # also: start:lucee6, start:2023, start:2025 (Adobe CF),
                                      #       start:boxlang-cfml
box run-script stop:lucee5            # port 60299 for every engine
box run-script logs:lucee5

box run-script format                 # cfformat; CI runs format:check, so format before committing
box run-script build:module           # the distributable zip

# ALWAYS check before starting a server: the port is shared (with other repos too).
box server list
```

## Running tests

With a server running, open the TestBox runner:

```
http://127.0.0.1:60299/tests/runner.cfm                                             # full suite
http://127.0.0.1:60299/tests/runner.cfm?reporter=text                               # plain text
http://127.0.0.1:60299/tests/runner.cfm?bundles=tests.specs.unit.OriginVerifierTest # one bundle
http://127.0.0.1:60299/tests/runner.cfm?directory=tests.specs.unit                  # one directory
```

Add `&fwreinit=1` after changing `ModuleConfig.cfc`, an interceptor, or harness config.

CFML specs live in `test-harness/tests/specs/` (`unit/`, `integration/`). 

[docs/testing.md](docs/testing.md) covers how to write a spec.

## Code style

- **Method Javadocs:** every method, public and private, carries a javadoc block with `@param` lines.
- **Formatter:** cfformat is ON in this repo. Run `box run-script format` before committing; CI fails on
    `format:check`.
- **Dependency injection:** prefer `property name="verifier" inject="OriginVerifier@originguard"` over
    `getInstance()`.
- **PRC vs RC:** `prc` for internal / server-set data, `rc` for raw user input. Always validate `rc`.
- **Framework reinit:** `?fwreinit=true`.
- **Cross-engine:** see the tripwires above. All three engines, always.
- Avoid em-dashes in prose unless they genuinely aid clarity.
- Simplicity is king. Favor the simplest solution that works, and avoid cleverness. If you find yourself writing a lot of code to solve a problem, consider whether the problem is worth solving.
- Prioritize clean readable code suitable for a new/junior developer.

## Where new knowledge goes

When you learn something worth keeping, pick the right file. Do not default to this one.

- A rule whose violation is **silent**, and that the code gives you no warning about → a tripwire here.
- How a **subsystem** works, its contracts and its gotchas → `docs/<topic>.md`.
- **What changed and why** → `changelog.md`, the dated changelog, newest first. Plain English, examples over
  prose, written for a developer new to the codebase.
- **End-user instructions** → `README.md` or `docs/README.md`. Written in plain english for a non-technical or beginning developer audience, consise language and examples. Instructions for a host to install, configure, and use this module.

## Communication style

Write comments, plans, and explanations for a newer/junior developer or intern still learning the codebase. Prefer clear, plain language over dense jargon. Briefly explain non-obvious framework behavior, conventions, or architectural decisions. Keep explanations practical, concise, and easy to scan. Challenge me or push back if you think I am going down the wrong path, introducing unnecessary complexity, or making a decision that will make future maintenance harder. Let me know if I am introducing code-smells, and suggest a better approach. If something I say is unclear, ask me questions until you have a solid understanding.

## AI resources

`.agents/manifest.json` holds the ColdBox CLI integration config. The `cfml` and `coldbox` guidelines are
generated into `.agents/guidelines/core/`, which is git-ignored and regenerated by the CLI, so never
hand-edit them. 

MCP documentation servers (see `.mcp.json`) for live framework docs: