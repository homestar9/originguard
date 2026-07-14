/**
 * MethodGuard
 *
 * TEMPORARY SHIM for a ColdBox bug. Tracked upstream and accepted by the maintainers at
 * https://ortussolutions.atlassian.net/browse/COLDBOX-1406
 *
 * WHEN THAT FIX SHIPS, DELETE ALL OF THIS:
 *   - this file
 *   - its registration line in ModuleConfig.cfc
 *   - test-harness/tests/specs/unit/MethodGuardTest.cfc
 *   - test-harness/tests/specs/integration/MethodGuardTest.cfc
 *   - the guinea `destroy` fixture action
 * Nothing else in OriginGuard depends on it. That isolation is the whole point of the file.
 *
 * THE BUG
 *
 * ColdBox's RequestContext.getHTTPMethod() is literally:
 *
 *     return getValue( "_method", CGI.REQUEST_METHOD );
 *
 * A spoofable request-collection value, with no whitelist. That much is deliberate: an HTML form can
 * only GET or POST, so `_method=DELETE` is how a browser form drives a RESTful DELETE route.
 *
 * The problem is that ColdBox validates `this.allowedMethods` against THAT SPOOFED VERB. So:
 *
 *     <img src="https://victim.com/admin/tags/1/delete?_method=DELETE">
 *
 * is a real browser GET -- the browser fires it itself, cross-site, with the victim's cookies -- yet
 * allowedMethods sees "DELETE", decides the verb is allowed, and runs the delete. This is not
 * theoretical. It deleted a record.
 *
 * THE FIX
 *
 * A request that ARRIVED on a safe verb may not CLAIM an unsafe one. When it does, delete the key.
 * getHTTPMethod() then falls back to the honest CGI verb, ColdBox's own allowedMethods check sees
 * "GET", does not match the action's declared "DELETE", and answers 405 through the OWNING handler's
 * onInvalidHTTPMethod. So this guard needs no scoping, no config, no denial event and no error view.
 * It knows about no module at all, which is why it protects a plugin exactly as well as the host app.
 *
 * IT RUNS UNCONDITIONALLY -- `enabled`, `secureList` and `mode` do NOT turn it off. Those settings
 * scope the ORIGIN check. A GET-reachable delete is a bug, not a policy, and no config line may
 * reopen it. Every strip is logged, so it is never silent.
 *
 * THE ONE THING IT CANNOT FIX: nothing can de-spoof before ROUTING. RoutingService reads the forged
 * verb during requestCapture(), which is before every interception point. See readme.md.
 */
component extends="coldbox.system.Interceptor" {

	/**
	 * The verbs that cannot mutate state (RFC 9110).
	 *
	 * Deliberately NOT the module's `safeMethods` setting, and deliberately not configurable. That
	 * setting means "verbs that skip the origin check", which a consumer may legitimately widen.
	 * This means "verbs that cannot mutate", which is a fact about HTTP, not a preference. Keeping
	 * them apart is also what leaves this component with zero dependencies, so a unit spec can just
	 * `new` it.
	 */
	variables.SAFE_METHODS = "GET,HEAD,OPTIONS";

	/**
	 * Strip a forged `_method` off every incoming request, before anything reads the verb.
	 *
	 * @event  The request context.
	 * @data   Intercept data (unused).
	 * @buffer Output buffer (unused).
	 * @rc     The request collection.
	 * @prc    The private request collection.
	 */
	function preProcess( event, data, buffer, rc, prc ){
		despoofMethod( arguments.event );
	}

	/**
	 * True when a request that ARRIVED on a safe verb CLAIMS an unsafe one.
	 *
	 * Public, and a pure function of two plain strings, on purpose. Under TestBox
	 * `cgi.request_method` is ALWAYS "GET" and no BaseTestCase helper can change it, so an
	 * integration spec can only ever reproduce the attack -- it physically cannot reproduce the
	 * LEGITIMATE case (a real browser POST carrying `_method=DELETE`, which is how every Delete
	 * button in every consuming app submits). Invert the transport check below and this module would
	 * strip `_method` from every legitimate POST, every Delete button everywhere would break in a
	 * real browser, and the whole CFML suite would stay green. The unit matrix driving this function
	 * is the only thing standing between us and that. Do not make it private.
	 *
	 * @transportMethod The verb the request ACTUALLY arrived on (cgi.request_method).
	 * @declaredMethod  The `_method` value riding in the request collection ("" when absent).
	 */
	boolean function isSpoofed( required string transportMethod, required string declaredMethod ){
		// An UNSAFE transport. `_method` here is the LEGITIMATE form-spoofing path (POST -> DELETE),
		// which is how every Delete button in every consuming app submits. Leave it alone.
		if ( !listFindNoCase( variables.SAFE_METHODS, trim( arguments.transportMethod ) ) ) {
			return false;
		}

		// A BLANK `_method` is normal, not an attack: a client that disables the field rather than
		// clearing it still posts an empty value.
		var declared = trim( arguments.declaredMethod );
		if ( !len( declared ) ) {
			return false;
		}

		// Safe transport, unsafe claim. That combination has no legitimate use, anywhere.
		return !listFindNoCase( variables.SAFE_METHODS, declared );
	}

	/**
	 * Remove a `_method` that rode in on a safe verb, so getHTTPMethod() falls back to the truth.
	 *
	 * @event The request context.
	 */
	private void function despoofMethod( required any event ){
		// Read the RAW key, NEVER event.getHTTPMethod(). BaseTestCase.request() -- and therefore
		// get()/post()/deleteRoute() -- MOCKS getHTTPMethod() while cgi.request_method stays the
		// runner's GET. A guard that read getHTTPMethod() would see "safe transport, unsafe verb" on
		// every mutating spec in every consuming app's suite: hundreds of bogus warnings, and a
		// guard whose own signal is worthless. Reading the raw key is also the more honest test, since
		// a forged `_method` is precisely what is being policed.
		if ( !arguments.event.valueExists( "_method" ) ) {
			return;
		}

		var declared = arguments.event.getValue( "_method", "" );

		if ( !isSpoofed( transportMethod = cgi.request_method, declaredMethod = declared ) ) {
			return;
		}

		log.warn(
			"OriginGuard stripped a forged _method. A #cgi.request_method# to '#arguments.event.getCurrentEvent()#' from #cgi.remote_addr# claimed _method='#declared#'."
		);

		arguments.event.removeValue( "_method" );
	}

}
