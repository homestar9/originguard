/**
 * OriginFirewallTest
 *
 * Proves the firewall wiring end to end: the interceptor registered, the host's moduleSettings
 * merged, the scope/verb gates work through a real execute() lifecycle, and a genuinely
 * external HTTP request gets a 403. The decision-matrix breadth lives in the unit spec; this
 * file is about the plumbing that a green unit suite cannot see.
 *
 * The runner request itself is a GET, so cgi.request_method is always safe here. Mocking
 * getHTTPMethod() to POST still forces verification because the firewall checks BOTH verbs
 * (the `_method` spoof defence). The black-box specs at the bottom cover the real-POST side.
 */
component extends="coldbox.system.testing.BaseTestCase" appMapping="root" {

	function run(){
		describe( "OriginFirewall interceptor", function(){
			beforeEach( function( currentSpec ){
				setup();
				variables.firewall = getController()
					.getInterceptorService()
					.getInterceptor( "OriginFirewall@originguard" );
			} );

			afterEach( function( currentSpec ){
				// Some specs mutate the live module settings; put every knob back so specs
				// stay order-independent.
				variables.firewall.getSettings()[ "enabled" ] = true;
				variables.firewall.getSettings()[ "allowedOrigins" ] = [];
				variables.firewall.getSettings()[ "denialEvent" ] = "originguard:errors.onBlocked";
				variables.firewall.getSettings()[ "secureList" ] = "*";
				variables.firewall.getSettings()[ "whiteList" ] = "";
				variables.firewall.getSettings()[ "mode" ] = "block";
			} );

			it( "sees the host's moduleSettings overrides (config actually merged)", function(){
				expect( variables.firewall.getSettings().secureList ).toBe( "*" );
			} );

			it( "blocks a cross-site POST to a protected event and renders the default 403", function(){
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBe( "guinea:main.save" );
				expect( result.getPrivateValue( "originBlockReason", "" ) ).toBe( "sec-fetch-site:cross-site" );
				expect( result.getRenderedContent() ).toInclude( "Request Blocked" );
				expect( result.getRenderData().statusCode ).toBe( "403" );
			} );

			it( "allows a same-origin POST through to the handler", function(){
				var oEvent = mockRequest( { "sec-fetch-site" : "same-origin" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "skips verification when both verbs are safe, even with hostile headers", function(){
				// No getHTTPMethod() mock: ColdBox and cgi both see the runner's GET.
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" } );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "never intercepts an error renderer, even inside a protected module", function(){
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:errors.onOriginFailure", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea custom denial" );
			} );

			it( "lets everything through when the kill switch is off", function(){
				variables.firewall.getSettings()[ "enabled" ] = false;
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "trusts a configured allowlist origin over a hostile Sec-Fetch-Site", function(){
				variables.firewall.getSettings()[ "allowedOrigins" ] = [ "partner.example.org" ];
				var oEvent = mockRequest(
					{
						"sec-fetch-site" : "cross-site",
						"origin"         : "https://partner.example.org"
					},
					"POST"
				);
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "protects root (non-module) events under the default '*' secureList", function(){
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "main.index", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBe( "main.index" );
				expect( result.getRenderedContent() ).toInclude( "Request Blocked" );
			} );

			it( "exempts a root-app errors handler even under '*'", function(){
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "errors.onOops", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "root error page" );
			} );

			it( "goes dormant when the secureList is empty (service mode)", function(){
				variables.firewall.getSettings()[ "secureList" ] = "";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "leaves events outside a scoped secureList alone", function(){
				variables.firewall.getSettings()[ "secureList" ] = "^guinea:";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "main.index", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
			} );

			it( "protects events inside a scoped secureList", function(){
				variables.firewall.getSettings()[ "secureList" ] = "^guinea:";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBe( "guinea:main.save" );
			} );

			it( "lets a whiteList module carve-out win over a '*' secureList", function(){
				variables.firewall.getSettings()[ "whiteList" ] = "^guinea:";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			// The payment-webhook case: one action is deliberately cross-site, but the rest of
			// its module must stay behind the firewall. These two specs are a pair.
			it( "whiteLists a single action", function(){
				variables.firewall.getSettings()[ "whiteList" ] = "^guinea:api\.webhook$";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:api.webhook", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea webhook" );
			} );

			it( "still protects the siblings of a whiteListed action", function(){
				variables.firewall.getSettings()[ "whiteList" ] = "^guinea:api\.webhook$";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBe( "guinea:main.save" );
			} );

			it( "logs instead of blocking in monitor mode (staged rollout)", function(){
				variables.firewall.getSettings()[ "mode" ] = "monitor";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "routes a rejection to a consumer-configured denialEvent", function(){
				variables.firewall.getSettings()[ "denialEvent" ] = "guinea:errors.onOriginFailure";
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" }, "POST" );
				var result = execute( event = "guinea:main.save", renderResults = true );
				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBe( "guinea:main.save" );
				expect( result.getRenderedContent() ).toInclude( "guinea custom denial" );
			} );
		} );

		describe( "OriginFirewall pattern matching", function(){
			// isInPattern() is private, so expose it once and drive the edge cases directly.
			// The specs above prove the wiring; these prove the matcher itself.
			beforeEach( function( currentSpec ){
				setup();
				variables.matcher = makePublic(
					getController().getInterceptorService().getInterceptor( "OriginFirewall@originguard" ),
					"isInPattern"
				);
			} );

			it( "treats '*' as every event, without handing a bare '*' to the regex engine", function(){
				// A lone "*" is a dangling quantifier and would throw if it reached reFindNoCase.
				expect( variables.matcher.isInPattern( "guinea:main.save", [ "*" ] ) ).toBeTrue();
				expect( variables.matcher.isInPattern( "main.index", [ "*" ] ) ).toBeTrue();
			} );

			it( "matches nothing when the pattern list is empty or blank", function(){
				expect( variables.matcher.isInPattern( "main.index", [] ) ).toBeFalse();
				expect( variables.matcher.isInPattern( "main.index", [ "", "   " ] ) ).toBeFalse();
			} );

			it( "matches case-insensitively", function(){
				expect( variables.matcher.isInPattern( "Admin:Users.Delete", [ "^admin:" ] ) ).toBeTrue();
			} );

			it( "is an UNANCHORED find, so patterns need their own '^'", function(){
				// This is the cbsecurity semantic, and the reason every example anchors.
				expect( variables.matcher.isInPattern( "main.adminIndex", [ "admin" ] ) ).toBeTrue();
				expect( variables.matcher.isInPattern( "main.adminIndex", [ "^admin" ] ) ).toBeFalse();
			} );

			it( "matches if ANY pattern in the list hits", function(){
				expect( variables.matcher.isInPattern( "api:sso.consume", [ "^admin:", "^api:" ] ) ).toBeTrue();
				expect( variables.matcher.isInPattern( "main.index", [ "^admin:", "^api:" ] ) ).toBeFalse();
			} );

			it( "can pin a single action with an anchored pattern", function(){
				var pattern = [ "^guinea:api\.webhook$" ];
				expect( variables.matcher.isInPattern( "guinea:api.webhook", pattern ) ).toBeTrue();
				expect( variables.matcher.isInPattern( "guinea:api.webhookList", pattern ) ).toBeFalse();
				expect( variables.matcher.isInPattern( "guinea:main.save", pattern ) ).toBeFalse();
			} );
		} );

		describe( "OriginFirewall over real HTTP (black box)", function(){
			it( "answers a real cross-site POST with a 403", function(){
				var httpResult = "";
				cfhttp(
					url     = "http://#cgi.http_host#/index.cfm?event=guinea:main.save",
					method  = "post",
					result  = "httpResult",
					timeout = 30
				) {
					cfhttpparam(
						type  = "header",
						name  = "Sec-Fetch-Site",
						value = "cross-site"
					);
				}
				// statusCode is the text form ("403 Forbidden") on every engine; the numeric
				// status_code key is Lucee-only.
				expect( listFirst( httpResult.statusCode, " " ) ).toBe( "403" );
				expect( httpResult.fileContent ).toInclude( "Request Blocked" );
			} );

			it( "allows a real headerless POST (curl / server-to-server is not a CSRF vector)", function(){
				var httpResult = "";
				cfhttp(
					url     = "http://#cgi.http_host#/index.cfm?event=guinea:main.save",
					method  = "post",
					result  = "httpResult",
					timeout = 30
				) {
					// Adobe refuses a POST with zero params; a form field does not add any
					// origin headers, so the request still looks like curl to the firewall.
					cfhttpparam(
						type  = "formfield",
						name  = "dummy",
						value = "1"
					);
				}
				expect( listFirst( httpResult.statusCode, " " ) ).toBe( "200" );
				expect( httpResult.fileContent ).toInclude( "guinea saved" );
			} );
		} );
	}

	/**
	 * Mock the current request context so the firewall sees the given headers (unstubbed header
	 * reads fall through to the caller-supplied default, like the real context) and, optionally,
	 * an unsafe HTTP verb.
	 *
	 * @headerValues Header name/value pairs the fake browser sends.
	 * @httpMethod   Leave empty to keep the runner's real verb (GET).
	 */
	private any function mockRequest( required struct headerValues, string httpMethod = "" ){
		var stubValues = arguments.headerValues;
		var oEvent     = prepareMock( getRequestContext() );
		oEvent.$(
			method   = "getHTTPHeader",
			callback = function( required string header, string defaultValue = "" ){
				if ( structKeyExists( stubValues, arguments.header ) ) {
					return stubValues[ arguments.header ];
				}
				return arguments.defaultValue;
			}
		);
		if ( len( arguments.httpMethod ) ) {
			oEvent.$( "getHTTPMethod", arguments.httpMethod );
		}
		return oEvent;
	}

}
