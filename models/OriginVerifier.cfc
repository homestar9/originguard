/**
 * OriginVerifier
 *
 * Decides whether an unsafe (state-changing) request came from an allowed origin, using the
 * browser's own Sec-Fetch-Site, Origin, and Referer headers. This is the Go 1.25
 * http.CrossOriginProtection algorithm: no tokens, no sessions, no storage.
 *
 * Pure and stateless: the same inputs always give the same verdict. Consumers either let the
 * OriginFirewall interceptor call this automatically, or inject it and call verify() themselves.
 */
component singleton {

	/**
	 * Convenience wrapper: pull the relevant headers off a ColdBox event and evaluate them.
	 *
	 * @event  The request context (anything answering getHTTPHeader( header, defaultValue )).
	 * @config Struct of { enabled:boolean, allowedOrigins:array, trustUpstream:boolean }.
	 *
	 * @return { allowed:boolean, reason:string } -- reason is for logging, never for control flow.
	 */
	struct function verify( required any event, required struct config ){
		var requestHeaders = {
			"origin"       : trim( arguments.event.getHTTPHeader( "origin", "" ) ),
			"secFetchSite" : lCase( trim( arguments.event.getHTTPHeader( "sec-fetch-site", "" ) ) ),
			"referer"      : trim( arguments.event.getHTTPHeader( "referer", "" ) )
		};
		return evaluateHeaders(
			headers     = requestHeaders,
			config      = arguments.config,
			requestHost = resolveHost( arguments.event, arguments.config )
		);
	}

	/**
	 * The five-step decision, engine-agnostic so a unit test can drive it with a plain struct.
	 *
	 * @headers     Struct of { origin, secFetchSite, referer }. Missing keys are treated as absent headers.
	 * @config      Struct of { enabled:boolean, allowedOrigins:array }.
	 * @requestHost The request's own host[:port] to compare against. Normalized internally.
	 *
	 * @return { allowed:boolean, reason:string } -- reason is for logging, never for control flow.
	 */
	struct function evaluateHeaders(
		required struct headers,
		required struct config,
		required string requestHost
	){
		// 0. The kill switch. When protection is off, everything is allowed. Both the interceptor
		//    and service-mode consumers share this so nobody has to reimplement it.
		if ( !isEnabled( arguments.config ) ) {
			return { "allowed" : true, "reason" : "disabled" };
		}

		var allowedList = getConfiguredOrigins( arguments.config );
		var ownHost     = normalizeOrigin( arguments.requestHost );
		var asserted    = "";
		if ( structKeyExists( arguments.headers, "origin" ) ) {
			asserted = trim( arguments.headers.origin );
		}

		// 1. A CONFIGURED allowlist entry blesses a trusted cross-origin caller -- it beats even a
		//    hostile Sec-Fetch-Site. Only the configured list gets this power; the request's own
		//    host waits until step 3 (below Sec-Fetch-Site), or its scheme-ignoring match would
		//    reopen the http->https hole that Sec-Fetch-Site closes.
		if ( len( asserted ) && isInList( allowedList, normalizeOrigin( asserted ) ) ) {
			return { "allowed" : true, "reason" : "allowlist" };
		}

		// 2. Sec-Fetch-Site is authoritative when present, and it is SCHEMEFUL: the browser
		//    itself tells us whether the request is same-origin. "none" means a direct
		//    navigation (typed URL, bookmark), which is not a CSRF vector.
		var fetchSite = "";
		if ( structKeyExists( arguments.headers, "secFetchSite" ) ) {
			fetchSite = lCase( trim( arguments.headers.secFetchSite ) );
		}
		if ( len( fetchSite ) ) {
			var fetchSiteOk = ( fetchSite == "same-origin" || fetchSite == "none" );
			return {
				"allowed" : fetchSiteOk,
				"reason"  : "sec-fetch-site:" & fetchSite
			};
		}

		// 3. No fetch metadata (older browser): fall back to the scheme-ignoring Origin
		//    comparison against the allowlist plus our own host. "null" never matches a real
		//    host, so sandboxed iframes / data: documents are rejected with no special case.
		if ( len( asserted ) ) {
			var originOk = matchesEffective( asserted, allowedList, ownHost );
			if ( originOk ) {
				return { "allowed" : true, "reason" : "origin-match" };
			}
			return { "allowed" : false, "reason" : "origin-mismatch" };
		}

		// 4. No Origin either: the Referer is the last signal an old browser leaves.
		var refererValue = "";
		if ( structKeyExists( arguments.headers, "referer" ) ) {
			refererValue = trim( arguments.headers.referer );
		}
		if ( len( refererValue ) ) {
			var refererOk = matchesEffective( refererValue, allowedList, ownHost );
			if ( refererOk ) {
				return { "allowed" : true, "reason" : "referer-match" };
			}
			return { "allowed" : false, "reason" : "referer-mismatch" };
		}

		// 5. No browser signal at all -> not a browser (curl, TestBox, server-to-server) -> not a
		//    CSRF vector. ALLOW. This rule is load-bearing for every non-browser caller.
		return { "allowed" : true, "reason" : "absent" };
	}

	/**
	 * The configured allowlist, normalized, as an array. Exposed so tests and consumers can
	 * assert exactly what the verifier will trust.
	 *
	 * @config Struct that may contain allowedOrigins:array.
	 */
	array function getAllowedOrigins( required struct config ){
		return listToArray( getConfiguredOrigins( arguments.config ) );
	}

	/**
	 * Protection is ON unless the config explicitly turns it off. A missing or non-boolean
	 * `enabled` key fails closed (protection stays on).
	 *
	 * @config The verifier config struct.
	 */
	private boolean function isEnabled( required struct config ){
		if ( structKeyExists( arguments.config, "enabled" ) && isBoolean( arguments.config.enabled ) ) {
			return arguments.config.enabled;
		}
		return true;
	}

	/**
	 * Compare the challenger (an Origin or Referer value) against the configured allowlist PLUS
	 * the request's own host. Both are always trusted in the no-fetch-metadata fallback:
	 * configuring an allowlist must never stop a site from trusting itself.
	 *
	 * The parameter is named `challenger` on purpose: on Lucee, a caller local with the same name
	 * as a positional parameter mis-resolves, so callee parameter names must never collide with
	 * caller locals.
	 *
	 * @challenger  The raw header value to test.
	 * @allowedList Comma list of normalized allowlist hosts (may be empty).
	 * @requestHost The normalized request host.
	 */
	private boolean function matchesEffective(
		required string challenger,
		required string allowedList,
		required string requestHost
	){
		var effectiveList = listAppend( arguments.allowedList, arguments.requestHost );
		return isInList( effectiveList, normalizeOrigin( arguments.challenger ) );
	}

	/**
	 * Normalize the configured allowedOrigins array into a comma list of host[:port] entries.
	 * Blank or non-array input yields an empty list (nothing extra is trusted).
	 *
	 * @config Struct that may contain allowedOrigins:array.
	 */
	private string function getConfiguredOrigins( required struct config ){
		var normalizedList = "";
		if ( structKeyExists( arguments.config, "allowedOrigins" ) && isArray( arguments.config.allowedOrigins ) ) {
			for ( var entry in arguments.config.allowedOrigins ) {
				var normalized = normalizeOrigin( entry );
				if ( len( normalized ) ) {
					normalizedList = listAppend( normalizedList, normalized );
				}
			}
		}
		return normalizedList;
	}

	/**
	 * Case-insensitive exact-item match against a comma list. NOT named `listContains` because
	 * that built-in does SUBSTRING matching -- shadowing it invites silent semantic drift.
	 *
	 * @list  The comma list to search.
	 * @value The exact item to find.
	 */
	private boolean function isInList( required string list, required string value ){
		return len( arguments.value ) && listFindNoCase( arguments.list, arguments.value ) > 0;
	}

	/**
	 * Lowercased host[:port]. The scheme is deliberately ignored (a TLS-terminating proxy needs
	 * no config; the schemeful case is Sec-Fetch-Site's job). Strips the scheme, any path, and
	 * the default ports :80/:443 (browsers omit them from Origin, but Referers and proxy-set
	 * hosts sometimes carry them).
	 *
	 * @value A raw origin, referer, or host value.
	 */
	private string function normalizeOrigin( required string value ){
		var normalized = lCase( trim( arguments.value ) );
		normalized     = reReplace( normalized, "^https?://", "" );
		normalized     = listFirst( normalized, "/" );
		normalized     = reReplace( normalized, ":(80|443)$", "" );
		return normalized;
	}

	/**
	 * The request's own host, honouring X-Forwarded-Host ONLY when config.trustUpstream is true
	 * (a Host-rewriting reverse proxy). Chained proxies append to the header
	 * ("client.example.com, proxy.internal"), so only the first entry counts. Falls back to
	 * cgi.http_host (fail closed).
	 *
	 * @event  The request context.
	 * @config Struct that may contain trustUpstream:boolean.
	 */
	private string function resolveHost( required any event, required struct config ){
		var hostValue = "";
		if (
			structKeyExists( arguments.config, "trustUpstream" )
			&& isBoolean( arguments.config.trustUpstream )
			&& arguments.config.trustUpstream
		) {
			hostValue = trim( arguments.event.getHTTPHeader( "x-forwarded-host", "" ) );
			hostValue = trim( listFirst( hostValue, "," ) );
		}
		if ( !len( hostValue ) ) {
			hostValue = cgi.http_host;
		}
		return normalizeOrigin( hostValue );
	}

}
