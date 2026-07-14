# Testing

How the test suite is organized and how to write a spec. For the commands to start a server and
open the runner, see [AGENTS.md](../AGENTS.md).

## The three layers

| Bundle | Extends | What it proves |
| --- | --- | --- |
| `tests/specs/unit/OriginVerifierTest.cfc` | `testbox.system.BaseSpec` | The full decision matrix, driven with plain structs. No ColdBox, no server state. This is where behavioral coverage lives. |
| `tests/specs/unit/MethodGuardTest.cfc` | `testbox.system.BaseSpec` | The `_method` de-spoofing matrix, driven with plain strings. Read the warning below before touching it. |
| `tests/specs/integration/OriginFirewallTest.cfc` | `coldbox.system.testing.BaseTestCase` | The wiring: interceptor registration, host settings merge, scope/verb gates through a real `execute()` lifecycle, and two real `cfhttp` POSTs. |
| `tests/specs/integration/MethodGuardTest.cfc` | `coldbox.system.testing.BaseTestCase` | The de-spoofer's wiring: the forged key is stripped and ColdBox's own `allowedMethods` answers 405. |
| `tests/specs/ModuleSpec.cfc` | `coldbox.system.testing.BaseTestCase` | A canary that the module registers and WireBox resolves `OriginVerifier@originguard`. |

Rule of thumb: new decision logic gets a unit spec row; new plumbing (settings, registration,
event routing) gets an integration spec.

## Writing a unit spec

Instantiate the verifier directly and call `evaluateHeaders()` with named arguments:

```cfc
var verifier = new originguard.models.OriginVerifier();
var verdict  = verifier.evaluateHeaders(
    headers     = { "secFetchSite" : "cross-site" },
    config      = { "enabled" : true },
    requestHost = "example.com"
);
expect( verdict.allowed ).toBeFalse();
```

Named arguments are not a style choice here: passing positionally from caller locals that share
the callee's parameter names is a Lucee tripwire (see AGENTS.md).

## Writing an integration spec

The harness runs with the module's real shipping defaults (`secureList = "*"`, `whiteList = ""`),
written out explicitly in `moduleSettings.originguard` in `test-harness/config/Coldbox.cfc` so the
specs prove the default rather than assume it. The fixtures the scope specs aim at:

| Fixture | Why it exists |
| --- | --- |
| `modules_app/guinea/handlers/Main.cfc` (`save`) | The ordinary protected action. |
| `modules_app/guinea/handlers/Main.cfc` (`destroy`) | A DELETE-only action (`this.allowedMethods`) plus an `onInvalidHTTPMethod` renderer, so `MethodGuardTest` can prove the whole chain: strip the forged `_method`, let ColdBox see the honest GET, answer 405 instead of deleting. Without the `onInvalidHTTPMethod`, ColdBox throws instead of 405ing and the spec blows up rather than asserting. |
| `modules_app/guinea/handlers/Api.cfc` (`webhook`) | A second handler in the same module, so a `whiteList` pattern can carve out ONE action and the specs can still prove `guinea:main.save` stays protected. |
| `modules_app/guinea/handlers/Errors.cfc` | A module-level errors handler, proving the errors exemption. |
| `handlers/Errors.cfc` (root) | The same exemption for root events. |

Specs that scope the firewall flip the live settings (`secureList` / `whiteList`) and restore them
in `afterEach`. To simulate a browser, mock the request context's header reads and verb, then run
the event:

```cfc
var oEvent = prepareMock( getRequestContext() );
oEvent.$( method = "getHTTPHeader", callback = function( header, defaultValue = "" ){
    return arguments.header == "sec-fetch-site" ? "cross-site" : arguments.defaultValue;
} );
oEvent.$( "getHTTPMethod", "POST" );
var result = execute( event = "guinea:main.save", renderResults = true );
```

The `$callback` style matters: unstubbed header reads must fall through to their default, exactly
like the real request context, or the verifier sees empty strings where it should see absence.

The runner request itself is a GET, so `cgi.request_method` is always safe in-process. Mocking
`getHTTPMethod()` still triggers verification because the firewall checks BOTH verbs. The
real-POST side is covered by the black-box `cfhttp` specs at the bottom of the integration
bundle, which need the server itself (they will not pass under a pure CLI runner).

Specs that mutate the live module settings (`variables.firewall.getSettings()[ ... ] = ...`)
must restore them in `afterEach` so specs stay order-independent.

## The verb tripwires

Both of these are silent. Neither is discoverable from the code. Read them before you write a spec
that touches an HTTP method.

### `get()` / `post()` / `request()` MOCK `getHTTPMethod()`, so use `execute()`

`BaseTestCase.request()` stubs `getHTTPMethod()` outright (`BaseTestCase.cfc:598`), and
`get()`/`post()`/`deleteRoute()` all route through it. `getHTTPMethod()` is the very function
`_method` feeds, so **a spec built on those helpers never exercises MethodGuard at all** - it will
pass whether the de-spoofer works or not.

`execute()` does not mock it. That is why `integration/MethodGuardTest.cfc` drives `execute()`, and
why it must keep doing so.

The same reasoning is why `MethodGuard.despoofMethod()` reads the raw `_method` key rather than
calling `getHTTPMethod()`. A guard that read `getHTTPMethod()` would see "safe transport, unsafe verb"
on every mutating spec in every consuming app's suite: hundreds of bogus warnings, and a guard whose
own signal is worthless.

### `cgi.request_method` is ALWAYS `GET` here, so the integration suite cannot cover the honest path

No `BaseTestCase` helper can change the runner's real verb. Which means an integration spec can only
ever reproduce the **attack** (a safe transport claiming an unsafe verb). It physically **cannot**
reproduce the **legitimate** case: a real browser `POST` carrying `_method=DELETE`, which is how every
Delete button in every consuming app submits.

So if `isSpoofed()`'s transport check were ever inverted, OriginGuard would strip `_method` from every
legitimate POST, every Delete button everywhere would break in a real browser, and **the entire CFML
suite would stay green.** That is the worst failure shape there is.

`unit/MethodGuardTest.cfc` is the only thing standing between us and it. It drives
`isSpoofed( transportMethod, declaredMethod )` as a pure string function - no ColdBox, no mock event -
and the `( "POST", "DELETE" ) -> false` row is the one that matters. Do not delete that bundle, and do
not make `isSpoofed()` private.

(The firewall's own dual-verb gate is the flip side of the same constraint: mocking `getHTTPMethod()`
still triggers verification because the gate checks BOTH verbs. The real-POST side is covered only by
the black-box `cfhttp` specs at the bottom of the firewall bundle, which need the server itself.)

## Gotchas already paid for

- `fwreinit=1` is required after touching `ModuleConfig.cfc`, interceptors, or harness config.
- Run BoxLang through the `boxlang-cfml` server (`box run-script start:boxlang-cfml`), which boots
  BoxLang with the `bx-compat-cfml` layer so the CFML runner works. There is no native-BoxLang
  server: native BoxLang crashed the runner before any spec executed (`InterceptorService.cfc:677`,
  "The key [NAME] was not found in the struct") on a ColdBox/BoxLang metadata incompatibility in the
  vendored framework, and the module ships no `.bx` code, so native support was dropped.
- Adobe's `cfhttp` result has no `status_code` key; use the text `statusCode` ("403 Forbidden").
- Adobe refuses a `POST` with zero `cfhttpparam` tags; add a dummy formfield.
- ColdBox appends `@moduleName` to interceptor names a module registers, so the firewall's
  registered name is `OriginFirewall@originguard` even though `ModuleConfig` says `OriginFirewall`.
