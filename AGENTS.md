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

[tbd]

## Engine support

Lucee 5+, Adobe ColdFusion 2023+, BoxLang 1+. Code must run on all three. See **Cross-engine** below.

## Directory layout

| Path | Purpose |
| --- | --- |
| `ModuleConfig.cfc` | Settings, dependencies, interceptors, breadcrumb rules, layouts. Read this first. |
| `models/` | Domain logic, one folder per entity, on top of the `Base*` classes. |
| `interceptors/` | `App.cfc` (registered as `cms`) and `Csrf.cfc`. |
| `test-harness/` | A full ColdBox app whose only job is to run the module under test. CFML specs live here. |
| `build/` | `Build.cfc`, which produces the distributable zip. |
| `docs/` | Subsystem reference docs. Dev-only, excluded from the build. |

## Cross-engine (Lucee 5 / ACF 2023 / BoxLang)

- **Never name a caller local the same as the callee's parameter** when passing it positionally. Lucee
    mis-resolves the argument and throws `UDFCasterException`, or worse, passes null.
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

box run-script start:lucee5           # also: start:lucee6, start:2023 (Adobe CF), start:boxlang
box run-script stop:lucee5            # default port 60301
box run-script logs:lucee5

box run-script build:module           # the distributable zip

# ALWAYS check before starting a server: the port is shared.
box server list
```

## Running tests

With a server running, open the TestBox runner:

```
http://127.0.0.1:[port]/tests/runner.cfm                              # full suite
http://127.0.0.1:[port]/tests/runner.cfm?reporter=text                # plain text
http://127.0.0.1:[port]/tests/runner.cfm?bundles=tests.specs.PageTest # one bundle
http://127.0.0.1:[port]/tests/runner.cfm?directory=tests.specs.unit   # one directory
```

CFML specs live in `test-harness/tests/specs/` (`unit/`, `integration/`). 

[docs/testing.md](docs/testing.md) covers how to write a spec.

## Code style

- **Method Javadocs:** every method, public and private, carries a javadoc block with `@param` lines.
- **Handler naming:** plural nouns (`Users.cfc`, `Pages.cfc`, `Categories.cfc`).
- **Dependency injection:** prefer `property name="service" inject="Service@cms"` over `getInstance()`.
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