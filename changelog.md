# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

----

## [Unreleased]

### Changed

* **CI is now tests-only; release automation removed.** This repo inherited the full Ortus module
  pipeline from its template, but releases here are handled manually (`box run-script release`) for
  now. Deleted `release.yml` (it fired on every push to `master` and tried to tag, publish to
  ForgeBox, sync to Ortus's S3 buckets, and Slack Ortus's channel - inert without their secrets, but a
  hazard the moment a `FORGEBOX_TOKEN` was added), `snapshot.yml` and the `prep_next_release` job (both
  targeted a `development` branch this fork does not have), and `cron.yml` (a daily scheduled test run).
  What stays is the part worth keeping: `tests.yml` (the reusable cross-engine matrix) and `pr.yml`,
  which still run the suite on every push and PR. Given the cross-engine tripwires in AGENTS.md bite
  silently, automated multi-engine test feedback is the one piece of CI this module genuinely needs.

* **Dependabot turned off.** Deleted `.github/dependabot.yml` and its four open branches. Two of its
  three ecosystems (`gradle`, `npm`) targeted files that do not exist here and errored silently; the
  third only bumped GitHub Action versions, which are pinned and can be updated by hand when needed.

## [2.1.0] => 2026-JUL-14

OriginGuard now strips a forged `_method` before anything reads the HTTP verb. Purely additive: no
settings changed, no behavior changed for any request that was not already an attack.

### The hole this closes

ColdBox's `event.getHTTPMethod()` is literally `getValue( "_method", CGI.REQUEST_METHOD )` - a
spoofable request value with no whitelist. That much is deliberate, because an HTML form can only GET
or POST, so `_method=DELETE` is how a browser form drives a RESTful DELETE route.

The problem is that ColdBox then validates `this.allowedMethods` against that *claimed* verb. So:

```html
<img src="https://your-app.com/admin/tags/1/delete?_method=DELETE">
```

is a real browser **GET** - the browser fires it itself, from any site on the internet, with the
victim's cookies - yet `allowedMethods` sees `DELETE`, decides the verb is allowed, and runs the
delete. **This is not theoretical. It deleted a record.**

Anyone who believes "my mutating actions declare `this.allowedMethods`, so they are not GET-reachable"
is wrong until something strips the forged key. That is exactly what OriginGuard's users believe.

### Added

* **`interceptors/MethodGuard.cfc`**, registered automatically alongside the firewall. The rule: *a
  request that arrived on a safe verb (GET/HEAD/OPTIONS) may not claim an unsafe one.* When one does,
  the `_method` key is deleted and the strip is logged at WARN.

  The legitimate direction is untouched. A real `POST` carrying `_method=DELETE` is how every Delete
  button in every app submits, and it still works.

### Design notes

* **It deletes the key rather than rendering a 403.** Dropping `_method` makes `getHTTPMethod()` fall
  back to the honest CGI verb, so ColdBox's own `allowedMethods` check sees `GET`, does not match the
  action's declared `DELETE`, and answers 405 through the OWNING handler's `onInvalidHTTPMethod`. That
  means MethodGuard needs no scoping, no config, no `denialEvent` and no error view - it knows about
  no module at all, so it protects a plugin exactly as well as the host app. A 403 and a 405 are
  equally inert and the record survives either way; the 405 is just far cheaper.

* **It reads no settings and cannot be switched off.** `enabled`, `secureList` and `mode` scope the
  *origin* check. None of them touches MethodGuard. A GET-reachable delete is a bug, not a policy, so
  no config line may reopen it. This is a deliberate departure from `enabled` being a true master
  switch, which is why every strip is logged.

* **The firewall's dual-verb gate did NOT change.** It still skips verification only when BOTH
  `cgi.request_method` and `getHTTPMethod()` are safe. That looks redundant now that MethodGuard runs
  first, and it is not: never gate on `getHTTPMethod()` alone, or a hostile cross-origin POST
  declaring `_method=GET` reads as safe and skips verification entirely. MethodGuard deliberately does
  not touch that direction, because a declared GET can only make `allowedMethods` *stricter* and
  cannot reach a mutation.

* **`isSpoofed()` is public, and that is not an accident.** Under TestBox `cgi.request_method` is
  always `GET`, so an integration spec can only ever reproduce the attack - it physically cannot
  reproduce the legitimate `POST -> DELETE` form path. Invert the transport check and OriginGuard would
  strip `_method` from every legitimate POST, every Delete button in every consuming app would break in
  a real browser, and the whole CFML suite would stay green. The pure-string unit matrix driving
  `isSpoofed()` is the only coverage of that branch that exists.

### Known limitation

**Nothing can de-spoof before routing.** `RoutingService` reads the forged verb during
`requestCapture()`, which runs before every interception point. Harmless while your router is
verb-agnostic (routes then resolve from the path and the forged verb changes nothing), but a router
using `.withVerbs()` or an action struct reopens the hole for any action that does not *also* declare
`this.allowedMethods`. It is a fact about ColdBox, not something this module can fix. See the readme.

### This is temporary

MethodGuard is a shim. The ColdBox maintainers have accepted
[COLDBOX-1406](https://ortussolutions.atlassian.net/browse/COLDBOX-1406) to fix `getHTTPMethod()`
upstream. When that ships, delete `interceptors/MethodGuard.cfc`, its registration line in
`ModuleConfig.cfc`, both `MethodGuardTest` bundles, and the `guinea` `destroy` fixture. Nothing else
in the module depends on it, which is exactly why it lives in its own file.

## [2.0.0] => 2026-JUL-14

The firewall stops thinking in *modules* and starts thinking in *event patterns*, and it is now ON
by default.

1.0 scoped protection by module name (`protectedModules` / `excludedModules`) and stayed dormant
until you configured it. Two problems with that. Module granularity is too coarse - you could not
exempt a single Stripe webhook action without unprotecting the whole module that owned it. And a
CSRF firewall that does nothing until you opt in will, in practice, do nothing.

So the scope is now a pair of `secureList` / `whiteList` regex patterns, the same shape ColdBox
developers already know from [cbsecurity's security rules](https://coldbox-security.ortusbooks.com/usage/untitled-1),
and `secureList` defaults to `"*"`.

### Breaking

* **`protectedModules` and `excludedModules` are removed.** They are not deprecated, they are gone.
  An app that still sets them gets the new `"*"` default instead, which is MORE protection than
  1.0 gave it, never less. It fails safe.
* **The firewall is ON by default.** Installing the module now protects every unsafe event. This
  includes a transitive install (a module that depends on OriginGuard only for service mode), which
  1.0 deliberately kept dormant. If you want the verifier without the firewall, set
  `secureList = ""`.
* The realistic breakage is narrow, because the verifier still allows any request with no browser
  signal at all (curl, scheduled jobs, server-to-server). What WILL start 403ing is the genuinely
  cross-site browser POST: SAML SSO assertions, 3-D Secure payment returns, embedded widgets. Run
  `mode = "monitor"` first to find yours - that is exactly what it is for.

Migration:

| 1.x | 2.0 |
| --- | --- |
| `protectedModules = [ "*" ]` | nothing - this is the default now |
| `protectedModules = [ "admin" ]` | `secureList = "^admin:"` |
| `protectedModules = [ "/" ]` | `secureList = "^[^:]+$"` |
| `excludedModules = [ "cbdebugger" ]` | `whiteList = "^cbdebugger:"` |
| `protectedModules = []` (service mode) | `secureList = ""` |

### Added

* `secureList` setting - which events to protect. A comma list (or array) of case-insensitive
  regex patterns matched against the ColdBox event. Defaults to `"*"`.
* `whiteList` setting - carve-outs from `secureList`, same pattern syntax. A whiteList hit always
  wins, so a carve-out never has to be ordered around anything. This is where the payment webhook
  goes: `whiteList = "^checkout:api\.webhook$"`.
* `test-harness/modules_app/guinea/handlers/Api.cfc` - a second fixture handler so the specs can
  prove a whiteList carves out ONE action (`guinea:api.webhook`) while its sibling
  (`guinea:main.save`) stays protected. Module-name scoping could never express that.

### Design notes

* **Matching is cbsecurity's, deliberately.** `reFindNoCase`, comma-delimited, and an UNANCHORED
  find - so `"admin"` also matches `main.adminIndex` and you must anchor with `^`. Copying the
  semantic (rather than improving it) means a pattern a developer already wrote for cbsecurity
  behaves the same here. The gotcha is documented in the readme instead of being papered over.
* **`"*"` is an alias, not a glob.** A lone `*` is a dangling quantifier and would throw if it
  reached the regex engine, so `isInPattern()` short-circuits it before `reFindNoCase` ever sees
  it. Everything else is a real regex. There is a spec pinning this on every engine.
* **Flat settings, not cbsecurity's array-of-rule-structs.** cbsecurity needs rule structs because
  each rule decides *who* may pass (roles, permissions, redirect vs override vs block). OriginGuard
  only ever decides protect / do not protect, so every rule would carry the same verdict. Two flat
  settings keep rule ordering out of the mental model entirely.
* **A malformed pattern throws.** No try/catch around the matcher. A typo in a security rule should
  be loud on the first unsafe request, not silently match nothing.
* The `errors` handler exemption is unchanged and still hardcoded, not a default whiteList entry -
  a denial page that gets firewalled is a bug, not a preference.

## [1.0.0] => 2026-JUL-14

First release. Header-based cross-origin (CSRF) protection for ColdBox, following the Go 1.25
`http.CrossOriginProtection` algorithm: `Sec-Fetch-Site` is authoritative, `Origin`/`Referer` are
fallbacks for older browsers, and a request with no browser signal at all is allowed (curl and
server-to-server calls are not CSRF vectors).

### Added

* `OriginVerifier@originguard` - the pure, stateless decision engine. `verify( event, config )`
  for ColdBox events, `evaluateHeaders( headers, config, requestHost )` for anything else.
* `OriginFirewall` interceptor - turnkey enforcement. Always registered, dormant until the host
  configures `protectedModules`. Handles `_method` verb-spoofing, exempts `errors` handlers
  (module and root), and routes rejections to a configurable `denialEvent`.
* Scope tokens: `protectedModules` accepts `"*"` (everything, root app included) and `"/"`
  (root events only) alongside module names, plus an `excludedModules` setting for carve-outs.
  `[ "*" ]` is the recommended config; the default stays empty so a transitive install (a
  module using service mode) never changes host behavior by itself.
* Default `originguard:errors.onBlocked` denial handler - a self-contained 403 (JSON for AJAX).
* Monitor mode (`mode = "monitor"`): logs what WOULD be blocked without enforcing, enabling the
  staged rollout the web.dev Fetch Metadata guidance recommends (monitor, tune, then block).
  Unknown mode values fail closed to `block`.
* Schemeful allowlist entries: `"https://partner.com"` pins the exact origin (Go's
  `AddTrustedOrigin` behavior); bare `"partner.com"` stays scheme-blind for
  TLS-terminating-proxy setups.
* Settings: `enabled`, `allowedOrigins`, `trustUpstream`, `protectedModules`, `excludedModules`,
  `safeMethods`, `mode`, `denialEvent`. See the readme for the full contract.

### Design notes (deviations from the original handoff spec, all deliberate)

* The kill switch (`enabled`) lives in the verifier itself, so service-mode consumers share it
  instead of reimplementing it.
* The no-fetch-metadata fallback compares `Origin`/`Referer` against the allowlist PLUS the
  request's own host. The spec had either/or, which would have made a site stop trusting itself
  the moment its first allowlist entry was configured.
* Two methods were renamed away from CFML built-ins after `evaluate()` resolved to the
  dynamic-evaluation BIF on Lucee: the core is `evaluateHeaders()`, the list helper `isInList()`
  (the `listContains()` BIF does substring matching - a security-relevant difference).
* `X-Forwarded-Host` honours only the first comma entry (chained proxies append), and
  `normalizeOrigin()` strips explicit default ports `:80`/`:443`.
