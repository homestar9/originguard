/**
 * OriginFirewall
 *
 * Turnkey enforcement of the OriginVerifier decision on every unsafe request. Registered
 * automatically by the module, and out of the box it protects EVERY event (`secureList = "*"`).
 * Scope it with `secureList` / `whiteList` event patterns, or set `secureList = ""` to switch
 * the firewall off entirely and use the verifier in service mode.
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

		// Fast exit: protection off, or nothing configured to secure.
		if ( !isBoolean( config.enabled ) || !config.enabled || !arrayLen( config.secureList ) ) {
			return;
		}

		// Skip only when BOTH the real verb AND ColdBox's view of it are safe. Never gate on
		// getHTTPMethod() alone: a hostile cross-origin POST declaring `_method=GET` would read as
		// safe and skip verification entirely.
		//
		// MethodGuard has already stripped any forged `_method` off a safe verb by the time we run,
		// so the second half of this AND looks redundant. It is not, for two reasons: a TestBox spec
		// mocks getHTTPMethod() while cgi.request_method stays the runner's GET (that is how the
		// integration bundle simulates an unsafe request), and it keeps this gate honest on the day
		// MethodGuard is deleted. Leave it alone.
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
				config.secureList,
				config.whiteList
			)
		) {
			return;
		}

		var verdict = variables.verifier.verify( arguments.event, config );
		if ( verdict.allowed ) {
			return;
		}

		// Monitor mode (the web.dev staged rollout): log what WOULD be blocked, let it through.
		// Run this for a while, add allowedOrigins/whiteList entries for what shows up, then
		// switch to block.
		if ( config.mode == "monitor" ) {
			log.warn( "OriginGuard monitor: would block '#targetEvent#' (#verdict.reason#)" );
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
			"enabled"        : true,
			"allowedOrigins" : [],
			"trustUpstream"  : false,
			"secureList"     : "*",
			"whiteList"      : "",
			"safeMethods"    : "GET,HEAD,OPTIONS",
			"mode"           : "block",
			"denialEvent"    : "originguard:errors.onBlocked"
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
		// Both pattern lists are documented as a comma list, but an array is the safer way to
		// write a pattern that itself contains a comma (a "{1,3}" quantifier, say), so accept both.
		if ( !isArray( config.secureList ) ) {
			config.secureList = listToArray( config.secureList );
		}
		if ( !isArray( config.whiteList ) ) {
			config.whiteList = listToArray( config.whiteList );
		}
		// Anything that is not explicitly "monitor" enforces (fail closed on typos).
		config.mode = lCase( trim( config.mode ) ) == "monitor" ? "monitor" : "block";
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
	 * Does this event fall inside the protected scope? The whiteList always wins over the
	 * secureList, so a carve-out never has to be ordered around anything.
	 *
	 * Error renderers (any handler named "errors", module or root) are always exempt so we
	 * never block a denial page -- including our own after an overrideEvent.
	 *
	 * @targetEvent The current event name, e.g. "myapp:content.save" or "content.save".
	 * @secureList  Array of patterns describing what to protect.
	 * @whiteList   Array of patterns carved out of the secureList.
	 */
	private boolean function isProtectedEvent(
		required string targetEvent,
		required array secureList,
		required array whiteList
	){
		if ( reFindNoCase( "(^|:)errors\.", arguments.targetEvent ) ) {
			return false;
		}
		if ( isInPattern( arguments.targetEvent, arguments.whiteList ) ) {
			return false;
		}
		return isInPattern( arguments.targetEvent, arguments.secureList );
	}

	/**
	 * Does the event match any pattern in the list? Patterns are case-insensitive regexes tested
	 * with an UNANCHORED find, the same semantics cbsecurity's security rules use: "^admin:"
	 * means "starts with admin:", while a bare "admin" would ALSO match "main.adminIndex".
	 * Anchor your patterns.
	 *
	 * The single token "*" is a convenience alias for "every event". It is not a glob, and on its
	 * own it is not even a valid regex (a dangling quantifier), so it is short-circuited here
	 * before reFindNoCase ever sees it.
	 *
	 * A malformed pattern throws, deliberately: a typo in a security rule should be loud.
	 *
	 * @targetEvent The current event name.
	 * @patterns    Array of regex patterns, and/or the "*" token.
	 */
	private boolean function isInPattern( required string targetEvent, required array patterns ){
		for ( var pattern in arguments.patterns ) {
			var cleaned = trim( pattern );
			if ( !len( cleaned ) ) {
				continue;
			}
			if ( cleaned == "*" ) {
				return true;
			}
			if ( reFindNoCase( cleaned, arguments.targetEvent ) ) {
				return true;
			}
		}
		return false;
	}

}
