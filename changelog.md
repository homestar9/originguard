# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

----

## [Unreleased]

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
* Settings: `enabled`, `allowedOrigins`, `trustUpstream`, `protectedModules`, `excludedModules`,
  `safeMethods`, `denialEvent`. See the readme for the full contract.

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
