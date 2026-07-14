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
component extends="coldbox.system.Interceptor" accessors="true" {

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

		// Scope: only events inside the configured protection scope, never error renderers.
		var targetEvent = arguments.event.getCurrentEvent();
		if (
			!isProtectedEvent(
				targetEvent,
				config.protectedModules,
				config.excludedModules
			)
		) {
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
			"excludedModules"  : [],
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
		if ( !isArray( config.excludedModules ) ) {
			config.excludedModules = listToArray( config.excludedModules );
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
	 * Does this event fall inside the protected scope? Scope entries are module names, plus
	 * two reserved tokens no real module can be named: "*" (every event, root app included)
	 * and "/" (root events only -- those with no module prefix). Exclusions always win.
	 *
	 * Error renderers (any handler named "errors", module or root) are always exempt so we
	 * never block a denial page -- including our own after an overrideEvent.
	 *
	 * @targetEvent      The current event name, e.g. "myapp:content.save" or "content.save".
	 * @protectedModules Array of module names and/or the "*" / "/" tokens.
	 * @excludedModules  Array of module names ("/" = the root app) carved out of the scope.
	 */
	private boolean function isProtectedEvent(
		required string targetEvent,
		required array protectedModules,
		required array excludedModules
	){
		if ( reFindNoCase( "(^|:)errors\.", arguments.targetEvent ) ) {
			return false;
		}

		// The event's module is everything before the first colon; root events have none and
		// are represented by the "/" token from here on.
		var scopeKey = "/";
		if ( listLen( arguments.targetEvent, ":" ) > 1 ) {
			scopeKey = trim( listFirst( arguments.targetEvent, ":" ) );
		}

		if ( isInScope( scopeKey, arguments.excludedModules ) ) {
			return false;
		}
		if ( isInScope( "*", arguments.protectedModules ) ) {
			return true;
		}
		return isInScope( scopeKey, arguments.protectedModules );
	}

	/**
	 * Is this scope key (a module name, or "/" for the root app) present in a configured
	 * scope list? Entries are trimmed and tolerate a trailing colon.
	 *
	 * @moduleKey The module name to look for, or "/" for root events, or the "*" token.
	 * @scopeList Array of configured module names / tokens.
	 */
	private boolean function isInScope( required string moduleKey, required array scopeList ){
		for ( var entry in arguments.scopeList ) {
			var cleaned = reReplace( trim( entry ), ":$", "" );
			if ( len( cleaned ) && cleaned == arguments.moduleKey ) {
				return true;
			}
		}
		return false;
	}

}
