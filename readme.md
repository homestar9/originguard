# OriginGuard

Modern, stateless CSRF protection for ColdBox applications. No tokens, no hidden form fields, no
session storage.

OriginGuard decides whether a state-changing request really came from your own site by reading the
headers the **browser itself** attaches to every request (`Sec-Fetch-Site`, `Origin`, `Referer`).
This is the same algorithm Go 1.25 ships as `http.CrossOriginProtection`, designed by Filippo
Valsorda. Because the browser controls these headers (an attacking page cannot forge them), a
simple header check replaces the whole token dance.

## Why not tokens?

Token CSRF protection works, but it drags a lot behind it: session state, token generation and
rotation, hidden fields in every form, special handling for AJAX, and broken forms whenever a
token expires. Header-based protection needs none of that. Every modern browser (since roughly
2020) sends `Sec-Fetch-Site` on every request, and older browsers still send `Origin` or
`Referer`, which OriginGuard falls back to.

## How the decision works

For each unsafe request (anything not GET/HEAD/OPTIONS), OriginGuard walks five steps and stops at
the first one that applies:

| Step | Signal | Verdict |
| --- | --- | --- |
| 1 | The `Origin` is in your configured `allowedOrigins` | **Allow** (a trusted partner site) |
| 2 | `Sec-Fetch-Site` is present | **Allow** only `same-origin` or `none`; reject `same-site` and `cross-site` |
| 3 | No fetch metadata, but an `Origin` header | **Allow** if it matches your host or the allowlist |
| 4 | No `Origin` either, but a `Referer` | Same comparison as step 3 |
| 5 | No browser signal at all | **Allow** - curl, TestBox, and server-to-server calls are not CSRF vectors |

Step 5 matters: a request with no browser headers at all is not coming from a browser, so it
cannot be cross-site request forgery. Blocking it would break every API client and scheduled job
for zero security gain.

## Requirements

- ColdBox 7+
- Lucee 5+, Adobe ColdFusion 2023+, or BoxLang 1+
- Zero runtime dependencies

## Installation

```bash
box install originguard
```

## Quick start: interceptor mode (turnkey)

Tell OriginGuard what to protect. For most apps the answer is "everything", and that is one line:

```cfc
// config/Coldbox.cfc
moduleSettings = {
    originguard = {
        protectedModules = [ "*" ]
    }
};
```

From then on, every unsafe request is verified. Rejected requests get a 403 from a small
built-in page (JSON if the request is AJAX). Events on an `errors` handler are never
intercepted, so your error pages always render.

`protectedModules` takes module names plus two reserved tokens:

| Entry | Protects |
| --- | --- |
| `"*"` | Everything: the root app and every module |
| `"/"` | Root (non-module) events only |
| `"admin"` | Events inside the `admin` module only |

Need carve-outs from a `"*"` scope? Use `excludedModules` (exclusions always win):

```cfc
moduleSettings = {
    originguard = {
        protectedModules = [ "*" ],
        excludedModules  = [ "cbdebugger" ]
    }
};
```

Protection is deliberately OFF until you write this config line. OriginGuard is also installed
transitively by modules that use it in service mode, and a dependency must never start blocking
requests in your app by itself. One line, you choose the scope, and `"*"` gives you everything.

### Custom denial page

Point `denialEvent` at your own handler to control what a blocked user sees:

```cfc
moduleSettings = {
    originguard = {
        protectedModules = [ "myapp" ],
        denialEvent      = "myapp:errors.onOriginFailure"
    }
};
```

Your handler receives two `prc` values: `prc.originBlockedEvent` (what was blocked) and
`prc.originBlockReason` (why, e.g. `sec-fetch-site:cross-site`). Remember to answer with a 403.

## Service mode (bring your own enforcement)

If you need custom failure handling per action (re-render a form, fail soft, log and continue),
skip the interceptor entirely: leave `protectedModules` empty and call the verifier yourself.

```cfc
component {

    property name="originVerifier" inject="OriginVerifier@originguard";
    property name="guardSettings"  inject="coldbox:modulesettings:originguard";

    function doLogin( event, rc, prc ){
        var verdict = originVerifier.verify( event, guardSettings );
        if ( !verdict.allowed ) {
            // your own failure path: re-render, relocate, log...
            return relocate( "main.login" );
        }
        // ... proceed
    }
}
```

`verify()` returns `{ allowed : boolean, reason : string }`. The `reason` is for logging only -
never branch on it.

## All settings

```cfc
moduleSettings = {
    originguard = {
        // Master switch. OFF means ZERO cross-origin protection from this module.
        enabled          = true,
        // Trusted cross-origin callers (host or host:port). Empty = only your own host.
        allowedOrigins   = [],
        // Honour X-Forwarded-Host. Only turn on behind a Host-rewriting reverse proxy.
        trustUpstream    = false,
        // Interceptor mode: module names, "*" (everything), and/or "/" (root events).
        // Empty = interceptor does nothing. [ "*" ] is the recommended config.
        protectedModules = [],
        // Interceptor mode: carve-outs from the scope above ("/" = root). Exclusions win.
        excludedModules  = [],
        // Interceptor mode: verbs that never need a check.
        safeMethods      = "GET,HEAD,OPTIONS",
        // Interceptor mode: where a blocked request lands.
        denialEvent      = "originguard:errors.onBlocked"
    }
};
```

## Things worth knowing

- **Allowlist entries are scheme-blind and beat `Sec-Fetch-Site`.** `allowedOrigins` entries are
  compared as `host[:port]` with the scheme ignored (so TLS-terminating proxies need no special
  config), and a match is trusted even when the browser reports `cross-site`. Practical rule:
  only allowlist hosts you would trust over plain `http`.
- **Behind a reverse proxy** that rewrites the `Host` header, set `trustUpstream = true` so the
  verifier compares against `X-Forwarded-Host` (first entry, when proxies chain) instead of the
  internal host. Only do this when a proxy you control sets that header, because clients can send
  it too.
- **The interceptor is always registered but dormant.** Until you configure `protectedModules`
  it exits after two struct reads, so installing OriginGuard for service mode adds no meaningful
  per-request cost.
- **Method-spoofing is covered.** The interceptor only skips verification when BOTH the real
  HTTP verb and ColdBox's view of it (which `_method=PUT` style spoofing changes) are safe.
- **Old browsers still work.** No `Sec-Fetch-Site` means the `Origin`/`Referer` fallbacks apply.
  A same-origin form post from a 2015 browser carries at least a `Referer` on your own host.
- **Legitimate cross-site POSTs need an allowlist entry.** Some flows deliver a browser POST
  from another site on purpose: SAML SSO (the IdP posts the assertion to you), 3-D Secure
  payment returns, embedded widgets. Under `protectedModules = [ "*" ]` those will 403 unless
  you add the sender to `allowedOrigins` or exclude that module.

## Contributing and tests

See [CONTRIBUTING.md](CONTRIBUTING.md). To run the suite locally:

```bash
box run-script install:dependencies
box run-script start:lucee5     # or start:2023, start:boxlang-cfml, ...
# open http://127.0.0.1:60299/tests/runner.cfm
```

## License

Apache License, Version 2.0.
