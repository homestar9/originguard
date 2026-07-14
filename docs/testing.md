# Testing

How the test suite is organized and how to write a spec. For the commands to start a server and
open the runner, see [AGENTS.md](../AGENTS.md).

## The three layers

| Bundle | Extends | What it proves |
| --- | --- | --- |
| `tests/specs/unit/OriginVerifierTest.cfc` | `testbox.system.BaseSpec` | The full decision matrix, driven with plain structs. No ColdBox, no server state. This is where behavioral coverage lives. |
| `tests/specs/integration/OriginFirewallTest.cfc` | `coldbox.system.testing.BaseTestCase` | The wiring: interceptor registration, host settings merge, scope/verb gates through a real `execute()` lifecycle, and two real `cfhttp` POSTs. |
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

## Gotchas already paid for

- `fwreinit=1` is required after touching `ModuleConfig.cfc`, interceptors, or harness config.
- Adobe's `cfhttp` result has no `status_code` key; use the text `statusCode` ("403 Forbidden").
- Adobe refuses a `POST` with zero `cfhttpparam` tags; add a dummy formfield.
- ColdBox appends `@moduleName` to interceptor names a module registers, so the firewall's
  registered name is `OriginFirewall@originguard` even though `ModuleConfig` says `OriginFirewall`.
