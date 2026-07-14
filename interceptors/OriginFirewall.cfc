/**
 * OriginFirewall
 *
 * Turnkey enforcement of the OriginVerifier decision on every unsafe request. Registered
 * automatically by the module, but it does NOTHING until the host configures
 * `protectedModules`, so service-mode consumers pay only a couple of struct reads per request.
 *
 * On a rejected request it stamps the prc and overrides the event to the configured
 * `denialEvent` -- it never aborts or writes to the response itself.
 */
component extends="coldbox.system.Interceptor" {

	// Property declarations must come before any this.* assignment (Adobe throws otherwise).
	property name="verifier" inject="OriginVerifier@originguard";
	property name="settings" inject="coldbox:modulesettings:originguard";

	/**
	 * Check every incoming request before its handler runs.
	 *
	 * @event  The request context.
	 * @data   Intercept data (unused).
	 * @buffer Output buffer (unused).
	 * @rc     The request collection.
	 * @prc    The private request collection.
	 */
	function preProcess( event, data, buffer, rc, prc ){
		var config = getConfig();

		// Fast exit: protection off, or nothing configured to protect.
		if ( !isBoolean( config.enabled ) || !config.enabled || !arrayLen( config.protectedModules ) ) {
			return;
		}

		// Skip only when BOTH the real verb AND ColdBox's view of it are safe. A `_method=POST`
		// spoof changes getHTTPMethod() but not cgi.request_method; a TestBox spec that mocks
		// getHTTPMethod() changes it the other way. Either one being unsafe means we verify.
		if (
			isSafeMethod( cgi.request_method, config.safeMethods )
			&& isSafeMethod( arguments.event.getHTTPMethod(), config.safeMethods )
		) {
			return;
		}

		// Scope: only events inside the configured module prefixes, never error renderers.
		var targetEvent = arguments.event.getCurrentEvent();
		if ( !isProtectedEvent( targetEvent, config.protectedModules ) ) {
			return;
		}

		var verdict = variables.verifier.verify( arguments.event, config );
		if ( verdict.allowed ) {
			return;
		}

		// Rejected: record what was blocked and why, then hand off to the denial renderer.
		arguments.prc[ "originBlockedEvent" ] = targetEvent;
		arguments.prc[ "originBlockReason" ]  = verdict.reason;
		arguments.event.overrideEvent( config.denialEvent );
	}

	/**
	 * Defensive settings reader: a host can replace the whole module settings struct, so merge
	 * whatever exists over our defaults and normalize the shapes the checks below rely on.
	 */
	private struct function getConfig(){
		var config = {
			"enabled"          : true,
			"allowedOrigins"   : [],
			"trustUpstream"    : false,
			"protectedModules" : [],
			"safeMethods"      : "GET,HEAD,OPTIONS",
			"denialEvent"      : "originguard:errors.onBlocked"
		};
		for ( var key in config ) {
			if ( structKeyExists( variables.settings, key ) ) {
				config[ key ] = variables.settings[ key ];
			}
		}
		// Tolerate an array of safe methods even though the contract says list.
		if ( isArray( config.safeMethods ) ) {
			config.safeMethods = arrayToList( config.safeMethods );
		}
		if ( !isArray( config.protectedModules ) ) {
			config.protectedModules = listToArray( config.protectedModules );
		}
		return config;
	}

	/**
	 * Is this HTTP verb exempt from verification?
	 *
	 * @verb        The HTTP method to test.
	 * @safeMethods Comma list of safe verbs.
	 */
	private boolean function isSafeMethod( required string verb, required string safeMethods ){
		return listFindNoCase( arguments.safeMethods, trim( arguments.verb ) ) > 0;
	}

	/**
	 * Does this event live inside one of the protected module prefixes? Error renderers
	 * (anything matching ":errors.") are always exempt so we never block a denial page --
	 * including our own after an overrideEvent.
	 *
	 * @targetEvent      The current event name, e.g. "myapp:content.save".
	 * @protectedModules Array of module name prefixes.
	 */
	private boolean function isProtectedEvent( required string targetEvent, required array protectedModules ){
		if ( reFindNoCase( ":errors\.", arguments.targetEvent ) ) {
			return false;
		}
		var prefixes = [];
		for ( var moduleName in arguments.protectedModules ) {
			// Strip blanks and a tolerated trailing colon, dedupe, and escape regex specials.
			var cleaned = reReplace( trim( moduleName ), ":$", "" );
			cleaned     = reReplace(
				cleaned,
				"([.\(\)\[\]\+\*\?\^\$\|\\])",
				"\\\1",
				"all"
			);
			if ( len( cleaned ) && !arrayFindNoCase( prefixes, cleaned ) ) {
				arrayAppend( prefixes, cleaned );
			}
		}
		if ( !arrayLen( prefixes ) ) {
			return false;
		}
		return reFindNoCase( "^(" & arrayToList( prefixes, "|" ) & "):", arguments.targetEvent ) > 0;
	}

}
