/**
 * MethodGuardTest (integration)
 *
 * Proves the de-spoofer's wiring end to end: the interceptor is registered, it strips the forged key
 * before ColdBox reads the verb, and ColdBox's own allowedMethods check then answers 405 through the
 * owning handler instead of running the delete.
 *
 * These specs MUST use execute(). BaseTestCase.request() -- and therefore get()/post()/deleteRoute()
 * -- MOCKS getHTTPMethod(), the very function `_method` feeds, so a spec built on those never
 * exercises MethodGuard at all. execute() leaves the real getHTTPMethod() in place while
 * cgi.request_method stays the runner's harmless GET, which is exactly the shape of the attack.
 *
 * The flip side of that, and the reason unit/MethodGuardTest.cfc exists: cgi.request_method is ALWAYS
 * "GET" here, so this bundle CANNOT reproduce the legitimate POST -> DELETE form path. Do not add a
 * spec here claiming to. That coverage lives in the unit matrix and nowhere else.
 *
 * TEMPORARY: delete this bundle with the rest of the shim when COLDBOX-1406 ships.
 */
component extends="coldbox.system.testing.BaseTestCase" appMapping="root" {

	function run(){
		describe( "MethodGuard de-spoofing", function(){
			beforeEach( function( currentSpec ){
				setup();
				variables.firewall = getController()
					.getInterceptorService()
					.getInterceptor( "OriginFirewall@originguard" );
			} );

			afterEach( function( currentSpec ){
				// One spec turns the kill switch off; put it back so specs stay order-independent.
				variables.firewall.getSettings()[ "enabled" ] = true;
			} );

			it( "is registered as its own interceptor", function(){
				var guard = getController().getInterceptorService().getInterceptor( "MethodGuard@originguard" );
				expect( isObject( guard ) ).toBeTrue();
			} );

			it( "strips a forged _method so ColdBox sees the honest GET", function(){
				// The <img src="/guinea/main/destroy?_method=DELETE"> drive-by, in one line.
				getRequestContext().setValue( "_method", "DELETE" );

				var result = execute( event = "guinea:main.destroy", renderResults = true );

				expect( result.getHTTPMethod() ).toBe( "GET", "the forged _method must be stripped" );
				expect( result.valueExists( "_method" ) ).toBeFalse( "the key itself must be gone" );
			} );

			it( "lets ColdBox's own allowedMethods answer 405, so the record survives", function(){
				getRequestContext().setValue( "_method", "DELETE" );

				var result = execute( event = "guinea:main.destroy", renderResults = true );

				expect( result.getRenderData().statusCode ).toBe( "405" );
				expect( result.getRenderedContent() ).toInclude( "guinea 405" );
				expect( result.getRenderedContent() ).notToInclude( "guinea destroyed" );
			} );

			it( "answers the real cross-site attack with a 405, never reaching the origin check", function(){
				// The full drive-by: a cross-site <img src> forging a DELETE. The hostile header has to
				// be here or the spec cannot tell "skipped the origin check" from "ran it and allowed".
				//
				// Once the key is stripped both verbs are safe, so the firewall never runs and the
				// request dies on ColdBox's own allowedMethods check instead. Both a 403 and a 405 are
				// inert and the record survives either way, but the 405 is strictly cheaper: it needs
				// none of the denial-rendering machinery and it comes from the OWNING handler, so it
				// works for any module without OriginGuard knowing that module exists.
				var oEvent = mockRequest( { "sec-fetch-site" : "cross-site" } );
				oEvent.setValue( "_method", "DELETE" );

				var result = execute( event = "guinea:main.destroy", renderResults = true );

				expect( result.getPrivateValue( "originBlockedEvent", "" ) ).toBeEmpty(
					"a stripped GET is a safe verb again, so the firewall must never see it"
				);
				expect( result.getRenderData().statusCode ).toBe( "405" );
				expect( result.getRenderedContent() ).notToInclude( "guinea destroyed" );
			} );

			it( "leaves a SAFE declared verb alone: that is not a spoof", function(){
				getRequestContext().setValue( "_method", "GET" );

				var result = execute( event = "guinea:main.save", renderResults = true );

				expect( result.getValue( "_method", "" ) ).toBe( "GET" );
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "is a no-op when there is no _method at all", function(){
				var result = execute( event = "guinea:main.save", renderResults = true );

				expect( result.valueExists( "_method" ) ).toBeFalse();
				expect( result.getRenderedContent() ).toInclude( "guinea saved" );
			} );

			it( "still strips when the kill switch is OFF: no config line may reopen this hole", function(){
				// `enabled` turns off the ORIGIN check. A GET-reachable delete is a bug, not a policy,
				// so MethodGuard reads no settings and cannot be switched off. This spec pins that.
				variables.firewall.getSettings()[ "enabled" ] = false;
				getRequestContext().setValue( "_method", "DELETE" );

				var result = execute( event = "guinea:main.destroy", renderResults = true );

				expect( result.getHTTPMethod() ).toBe( "GET" );
				expect( result.getRenderData().statusCode ).toBe( "405" );
			} );
		} );
	}

	/**
	 * Simulate a browser's headers on the request context.
	 *
	 * The $callback style matters: unstubbed header reads must fall through to their default, exactly
	 * like the real request context, or the verifier sees empty strings where it should see absence.
	 *
	 * Note there is NO getHTTPMethod() mock here, unlike OriginFirewallTest. Mocking it would defeat
	 * the entire point of this bundle: `_method` is what feeds getHTTPMethod(), so stubbing it out
	 * means nothing under test ever reads the forged key.
	 *
	 * @headerValues The headers this pretend browser sends.
	 */
	private any function mockRequest( required struct headerValues ){
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
		return oEvent;
	}

}
