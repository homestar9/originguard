# OriginGuard
![OriginGuard Logo](https://github.com/homestar9/originguard/blob/master/originguard-logo.avif?raw=true)

Modern, stateless CSRF protection for ColdBox applications. No tokens, no hidden form fields, no
session storage.

OriginGuard decides whether a state-changing request really came from your own site by reading the
headers the **browser itself** attaches to every request (`Sec-Fetch-Site`, `Origin`, `Referer`).
This is the same algorithm Go 1.25 ships as `http.CrossOriginProtection`, designed by [Filippo
Valsorda](https://words.filippo.io/csrf/). Because the browser controls these headers (an attacking page cannot forge them), a
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

There is no quick start. Install the module and **every unsafe request is protected**, no config
required. Rejected requests get a 403 from a small built-in page (JSON if the request is AJAX).
Events on an `errors` handler are never intercepted, so your error pages always render.

The config you eventually write is not the opt-in, it is the list of **exceptions**.

### Scoping with `secureList` and `whiteList`

If you have used [cbsecurity](https://coldbox-security.ortusbooks.com/usage/untitled-1)'s security
rules, this will look familiar. Two settings, both **case-insensitive regex patterns** matched
against the ColdBox event:

- **`secureList`** - what to protect. Defaults to `"*"`, which means every event.
- **`whiteList`** - carve-outs from the secureList. A whiteList hit always wins.

```cfc
// config/Coldbox.cfc
moduleSettings = {
    originguard = {
        // Protect everything (this is already the default - shown for clarity)...
        secureList = "*",
        // ...except the payment webhook, which a gateway posts to cross-site on purpose.
        whiteList  = "^checkout:api\.webhook$"
    }
};
```

Patterns are **regexes**, and they are matched with an unanchored *find* - exactly like
cbsecurity. That means `"admin"` also matches `main.adminIndex`, so **anchor your patterns with
`^`**. Here is the cookbook:

| Goal | Pattern |
| --- | --- |
| Everything | `*` |
| Root (non-module) events only | `^[^:]+$` |
| One module | `^admin:` |
| One handler | `^admin:users\.` |
| One exact action | `^admin:users\.delete$` |
| Two modules | `^admin:,^api:` |
| Nothing (firewall off) | `""` |

`"*"` is the one special case: it is a convenience alias for "every event", not a glob. Every
other pattern is a real regex.

Both settings take a **comma list** (`"^admin:,^api:"`) or an **array**
(`[ "^admin:", "^api:" ]`). Use the array form if a pattern contains a comma of its own - a
`{1,3}` quantifier, say - because the comma would otherwise split it in two.

### Safe rollout for an existing app (recommended)

If you are adding OriginGuard to an app that already has traffic, do **not** go straight to
enforcing. Follow the staged deployment the
[Fetch Metadata guidance](https://web.dev/articles/fetch-metadata) recommends - observe first,
then enforce:

```cfc
// Phase 1: still protecting everything, but only LOG what would be blocked
moduleSettings = {
    originguard = {
        mode = "monitor"
    }
};
```

Run that for a few days and watch your logs for `OriginGuard monitor:` warnings. Legitimate
cross-site flows will show up here - SAML SSO posts, payment-gateway returns, embedded widgets.
Add those senders to `allowedOrigins`, or their events to the `whiteList`, then remove
`mode = "monitor"` to start enforcing. Nothing breaks while you learn what your traffic really
looks like.

### Custom denial page

Point `denialEvent` at your own handler to control what a blocked user sees:

```cfc
moduleSettings = {
    originguard = {
        denialEvent = "myapp:errors.onOriginFailure"
    }
};
```

Your handler receives two `prc` values: `prc.originBlockedEvent` (what was blocked) and
`prc.originBlockReason` (why, e.g. `sec-fetch-site:cross-site`). Remember to answer with a 403.

## Service mode (bring your own enforcement)

If you need custom failure handling per action (re-render a form, fail soft, log and continue),
switch the firewall off with `secureList = ""` and call the verifier yourself. The verifier stays
fully available; only the interceptor goes dormant.

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
        enabled        = true,
        // Trusted cross-origin callers. "partner.com" trusts both schemes;
        // "https://partner.com" pins the scheme (recommended). Empty = only your own host.
        allowedOrigins = [],
        // Honour X-Forwarded-Host. Only turn on behind a Host-rewriting reverse proxy.
        trustUpstream  = false,
        // Firewall: which events to protect. Case-insensitive regex patterns (comma list or
        // array), matched with an unanchored find - anchor with "^". "*" = every event.
        // Empty = the firewall is off (service mode).
        secureList     = "*",
        // Firewall: carve-outs from secureList. Same syntax. A whiteList hit always wins.
        whiteList      = "",
        // Firewall: verbs that never need a check.
        safeMethods    = "GET,HEAD,OPTIONS",
        // Firewall: "block" enforces, "monitor" only logs would-be blocks.
        mode           = "block",
        // Firewall: where a blocked request lands.
        denialEvent    = "originguard:errors.onBlocked"
    }
};
```

## Things worth knowing

- **Allowlist entries beat `Sec-Fetch-Site`, so pin their scheme.** An allowlisted origin is
  trusted even when the browser reports `cross-site`. Write entries WITH a scheme
  (`"https://partner.com"`) so only that exact origin gets the power - the same behavior as
  Go's `AddTrustedOrigin`. A bare `"partner.com"` trusts both `http` and `https`; only use
  that form for hosts you would trust over plain `http`.
- **Behind a reverse proxy** that rewrites the `Host` header, set `trustUpstream = true` so the
  verifier compares against `X-Forwarded-Host` (first entry, when proxies chain) instead of the
  internal host. Only do this when a proxy you control sets that header, because clients can send
  it too.
- **Patterns are regexes and the match is unanchored.** `"admin"` matches `main.adminIndex`, not
  just the `admin` module. Anchor with `^`. This is cbsecurity's semantic, kept on purpose so the
  two modules read the same way.
- **Method-spoofing is covered, twice.** The firewall only skips verification when BOTH the real
  HTTP verb and ColdBox's view of it (which `_method=PUT` style spoofing changes) are safe. And
  MethodGuard, below, strips a forged `_method` before anything reads the verb at all.
- **Old browsers still work.** No `Sec-Fetch-Site` means the `Origin`/`Referer` fallbacks apply.
  A same-origin form post from a 2015 browser carries at least a `Referer` on your own host.
- **Legitimate cross-site POSTs need a whiteList or allowlist entry.** Some flows deliver a
  browser POST from another site on purpose: SAML SSO (the IdP posts the assertion to you),
  3-D Secure payment returns, embedded widgets. These will 403 unless you add the sender to
  `allowedOrigins` or the event to the `whiteList`. If you are retrofitting an existing app,
  `mode = "monitor"` will find them all for you before anything breaks.

## MethodGuard: the forged `_method` (and its one limitation)

OriginGuard also installs a second, much smaller interceptor called **MethodGuard**. You do not
configure it and you cannot switch it off. Here is what it does and why.

### The problem

ColdBox's `event.getHTTPMethod()` reads a spoofable request value:

```cfc
return getValue( "_method", CGI.REQUEST_METHOD );
```

That is on purpose. An HTML form can only GET or POST, so `_method=DELETE` is how a browser form
drives a RESTful DELETE route. The trouble is that ColdBox validates `this.allowedMethods` against
that *claimed* verb. So this:

```html
<img src="https://your-app.com/admin/tags/1/delete?_method=DELETE">
```

is a real browser **GET**, fired by the browser itself, from any site on the internet, with your
logged-in user's cookies attached. But `allowedMethods` sees `DELETE`, decides the verb is fine, and
runs the delete. **This is not theoretical. It deleted a record.**

If you believe "my mutating actions declare `this.allowedMethods`, so they are not reachable by GET",
you are wrong until something strips that forged `_method`.

### The fix

**A request that arrived on a safe verb (GET/HEAD/OPTIONS) may not claim an unsafe one.** When one
does, MethodGuard deletes the `_method` key. `getHTTPMethod()` then falls back to the honest verb,
ColdBox's own `allowedMethods` check sees `GET`, and answers **405 through your own handler's
`onInvalidHTTPMethod`**. Nothing to configure, and no denial page needed.

The legitimate direction is untouched: a real `POST` carrying `_method=DELETE` is exactly how every
Delete button in every app submits, and it still works.

**It ignores every setting on this page.** `enabled = false`, `secureList = ""` and `mode = "monitor"`
all turn off the *origin* check. None of them turns off MethodGuard. A GET-reachable delete is a bug,
not a policy, so no config line may reopen it. Every strip is logged at WARN, so it is never silent.

### The limitation you need to know about

**Nothing can de-spoof before routing.** ColdBox's `RoutingService` reads the forged verb while it
captures the request, which happens before every interception point in the framework. There is no
earlier hook, so this is a fact about ColdBox and not something this module can fix.

That is harmless if your router is verb-agnostic (no `.withVerbs()`, no action structs), because then
routes resolve from the path and a forged verb changes nothing.

**But if your router uses `.withVerbs()` or an action struct, the hole is still open** for any action
that does not *also* declare `this.allowedMethods` - the router will already have picked the
DELETE-mapped action off the forged verb before OriginGuard ever runs. Declare `this.allowedMethods`
on your mutating actions and you are covered either way.

### It is temporary

This is a shim. The ColdBox maintainers have accepted
[COLDBOX-1406](https://ortussolutions.atlassian.net/browse/COLDBOX-1406) to fix `getHTTPMethod()`
upstream. When that ships, MethodGuard will be removed from this module. Nothing you write depends on
it, so the removal will not affect your app.

## Upgrading from 1.x

**`protectedModules` and `excludedModules` are gone.** They were module-name lists; the
replacement is `secureList` / `whiteList` event patterns, and protection is now ON by default.
An app that still sets the old keys will simply have them ignored and get the new `"*"` default,
which is *more* protection than before, never less.

| 1.x | 2.0 |
| --- | --- |
| `protectedModules = [ "*" ]` | nothing - this is the default now |
| `protectedModules = [ "admin" ]` | `secureList = "^admin:"` |
| `protectedModules = [ "/" ]` | `secureList = "^[^:]+$"` |
| `excludedModules = [ "cbdebugger" ]` | `whiteList = "^cbdebugger:"` |
| `protectedModules = []` (service mode) | `secureList = ""` |

The one case that needs your attention: if you were relying on the interceptor being **dormant**
by default - because OriginGuard arrived transitively as some other module's dependency and you
only wanted the verifier - it is no longer dormant. Set `secureList = ""` to restore that.

## Contributing and tests

See [CONTRIBUTING.md](CONTRIBUTING.md). To run the suite locally:

```bash
box run-script install:dependencies
box run-script start:lucee5     # or start:2023, start:boxlang-cfml, ...
# open http://127.0.0.1:60299/tests/runner.cfm
```

## License

Apache License, Version 2.0.
