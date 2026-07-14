/**
 * OriginVerifierTest
 *
 * The exhaustive decision matrix for the shared brain. These specs drive evaluateHeaders() directly
 * with plain structs -- no ColdBox, no mock events -- so the security-critical logic is tested
 * once, cheaply, in isolation. The tripwire to remember: never pass positional arguments from
 * caller locals named like the callee's parameters (Lucee mis-resolves them), so every call
 * here uses named arguments.
 */
component extends="testbox.system.BaseSpec" {

	function beforeAll(){
		variables.verifier = new originguard.models.OriginVerifier();
	}

	/**
	 * Helper: run evaluateHeaders() against host "example.com" with protection on.
	 *
	 * @requestHeaders The headers struct to evaluate.
	 * @moduleConfig   Config overrides; enabled defaults to true.
	 */
	private struct function decide( struct requestHeaders = {}, struct moduleConfig = {} ){
		if ( !structKeyExists( arguments.moduleConfig, "enabled" ) ) {
			arguments.moduleConfig[ "enabled" ] = true;
		}
		return variables.verifier.evaluateHeaders(
			headers     = arguments.requestHeaders,
			config      = arguments.moduleConfig,
			requestHost = "example.com"
		);
	}

	function run(){
		describe( "Step 0: the kill switch", function(){
			it( "allows everything when disabled, even a hostile cross-site request", function(){
				var verdict = decide(
					requestHeaders = {
						"secFetchSite" : "cross-site",
						"origin"       : "https://evil.example.org"
					},
					moduleConfig = { "enabled" : false }
				);
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "disabled" );
			} );

			it( "stays ON when the enabled key is missing or junk (fails closed)", function(){
				expect( decide( requestHeaders = { "secFetchSite" : "cross-site" }, moduleConfig = {} ).allowed ).toBeFalse();
				var junkConfig = { "enabled" : "banana" };
				expect(
					variables.verifier.evaluateHeaders(
						headers     = { "secFetchSite" : "cross-site" },
						config      = junkConfig,
						requestHost = "example.com"
					).allowed
				).toBeFalse();
			} );
		} );

		describe( "Step 1: the configured allowlist", function(){
			it( "blesses a trusted cross-origin caller even against a hostile Sec-Fetch-Site", function(){
				var verdict = decide(
					requestHeaders = {
						"secFetchSite" : "cross-site",
						"origin"       : "https://partner.example.org"
					},
					moduleConfig = { "allowedOrigins" : [ "partner.example.org" ] }
				);
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "allowlist" );
			} );

			it( "matches bare-host allowlist entries case-insensitively, ignoring path and default port", function(){
				var verdict = decide(
					requestHeaders = {
						"secFetchSite" : "cross-site",
						"origin"       : "https://Partner.Example.org:443"
					},
					moduleConfig = { "allowedOrigins" : [ "Partner.Example.org/some/path" ] }
				);
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "allowlist" );
			} );

			it( "pins the scheme when an allowlist entry includes one (Go AddTrustedOrigin behavior)", function(){
				var pinnedConfig = { "allowedOrigins" : [ "https://partner.example.org" ] };
				var httpsVerdict = decide(
					requestHeaders = {
						"secFetchSite" : "cross-site",
						"origin"       : "https://partner.example.org"
					},
					moduleConfig = pinnedConfig
				);
				expect( httpsVerdict.allowed ).toBeTrue();
				expect( httpsVerdict.reason ).toBe( "allowlist" );

				// The http:// twin of a pinned https:// entry gets NO allowlist power.
				var httpVerdict = decide(
					requestHeaders = {
						"secFetchSite" : "cross-site",
						"origin"       : "http://partner.example.org"
					},
					moduleConfig = pinnedConfig
				);
				expect( httpVerdict.allowed ).toBeFalse();
				expect( httpVerdict.reason ).toBe( "sec-fetch-site:cross-site" );
			} );

			it( "does NOT give the request's own host allowlist power over Sec-Fetch-Site", function(){
				// A cross-site verdict from the browser is schemeful truth. An Origin that merely
				// LOOKS like our own host (e.g. http vs https) must not override it.
				var verdict = decide(
					requestHeaders = {
						"secFetchSite" : "cross-site",
						"origin"       : "http://example.com"
					}
				);
				expect( verdict.allowed ).toBeFalse();
				expect( verdict.reason ).toBe( "sec-fetch-site:cross-site" );
			} );
		} );

		describe( "Step 2: Sec-Fetch-Site is authoritative", function(){
			it( "allows same-origin", function(){
				var verdict = decide( requestHeaders = { "secFetchSite" : "same-origin" } );
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "sec-fetch-site:same-origin" );
			} );

			it( "allows none (direct navigation: typed URL, bookmark)", function(){
				expect( decide( requestHeaders = { "secFetchSite" : "none" } ).allowed ).toBeTrue();
			} );

			it( "rejects same-site (a subdomain is not us)", function(){
				var verdict = decide( requestHeaders = { "secFetchSite" : "same-site" } );
				expect( verdict.allowed ).toBeFalse();
				expect( verdict.reason ).toBe( "sec-fetch-site:same-site" );
			} );

			it( "rejects cross-site", function(){
				expect( decide( requestHeaders = { "secFetchSite" : "cross-site" } ).allowed ).toBeFalse();
			} );

			it( "normalizes casing and whitespace in the header value", function(){
				expect( decide( requestHeaders = { "secFetchSite" : "  Same-Origin " } ).allowed ).toBeTrue();
			} );
		} );

		describe( "Step 3: Origin fallback (no fetch metadata, older browser)", function(){
			it( "allows an Origin matching our own host", function(){
				var verdict = decide( requestHeaders = { "origin" : "https://example.com" } );
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "origin-match" );
			} );

			it( "rejects a foreign Origin", function(){
				var verdict = decide( requestHeaders = { "origin" : "https://evil.example.org" } );
				expect( verdict.allowed ).toBeFalse();
				expect( verdict.reason ).toBe( "origin-mismatch" );
			} );

			it( "rejects Origin: null (sandboxed iframe, data: document)", function(){
				expect( decide( requestHeaders = { "origin" : "null" } ).allowed ).toBeFalse();
			} );

			it( "still trusts our own host when an allowlist is configured", function(){
				// Configuring the first allowlist entry must never make a site stop trusting itself.
				var verdict = decide(
					requestHeaders = { "origin" : "https://example.com" },
					moduleConfig   = { "allowedOrigins" : [ "partner.example.org" ] }
				);
				expect( verdict.allowed ).toBeTrue();
			} );

			it( "treats explicit default ports as equal to no port", function(){
				expect( decide( requestHeaders = { "origin" : "https://example.com:443" } ).allowed ).toBeTrue();
				expect( decide( requestHeaders = { "origin" : "http://example.com:80" } ).allowed ).toBeTrue();
			} );

			it( "keeps non-default ports significant", function(){
				expect( decide( requestHeaders = { "origin" : "https://example.com:8443" } ).allowed ).toBeFalse();
				expect(
					variables.verifier.evaluateHeaders(
						headers     = { "origin" : "https://example.com:8443" },
						config      = { "enabled" : true },
						requestHost = "example.com:8443"
					).allowed
				).toBeTrue();
			} );
		} );

		describe( "Step 4: Referer fallback (no fetch metadata, no Origin)", function(){
			it( "allows a Referer on our own host, ignoring its path", function(){
				var verdict = decide( requestHeaders = { "referer" : "https://example.com/some/page.cfm" } );
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "referer-match" );
			} );

			it( "rejects a foreign Referer", function(){
				var verdict = decide( requestHeaders = { "referer" : "https://evil.example.org/attack" } );
				expect( verdict.allowed ).toBeFalse();
				expect( verdict.reason ).toBe( "referer-mismatch" );
			} );

			it( "allows an allowlisted Referer", function(){
				var verdict = decide(
					requestHeaders = { "referer" : "https://partner.example.org/form" },
					moduleConfig   = { "allowedOrigins" : [ "partner.example.org" ] }
				);
				expect( verdict.allowed ).toBeTrue();
			} );

			it( "matches a schemeful allowlist entry by Referer, ignoring the path", function(){
				var pinnedConfig = { "allowedOrigins" : [ "https://partner.example.org" ] };
				expect(
					decide(
						requestHeaders = { "referer" : "https://partner.example.org/some/form" },
						moduleConfig   = pinnedConfig
					).allowed
				).toBeTrue();
				expect(
					decide(
						requestHeaders = { "referer" : "http://partner.example.org/some/form" },
						moduleConfig   = pinnedConfig
					).allowed
				).toBeFalse();
			} );
		} );

		describe( "Step 5: no browser signal at all", function(){
			it( "allows a request with no origin headers (curl, server-to-server: not a CSRF vector)", function(){
				var verdict = decide();
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "absent" );
			} );

			it( "treats blank header values the same as absent ones", function(){
				var verdict = decide( requestHeaders = { "origin" : "", "secFetchSite" : "", "referer" : "" } );
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "absent" );
			} );
		} );

		describe( "getAllowedOrigins(): allowlist normalization", function(){
			it( "lowercases, strips paths/default ports, keeps explicit schemes, drops blanks", function(){
				var normalized = variables.verifier.getAllowedOrigins( {
					"allowedOrigins" : [
						" HTTPS://Partner.Example.org/ ",
						"",
						"http://other.example.org:443/deep/path",
						"api.example.org:8443",
						"Plain.Example.org/"
					]
				} );
				expect( normalized ).toBe( [
					"https://partner.example.org",
					"http://other.example.org",
					"api.example.org:8443",
					"plain.example.org"
				] );
			} );

			it( "returns an empty array when nothing (or junk) is configured", function(){
				expect( variables.verifier.getAllowedOrigins( {} ) ).toBeEmpty();
				expect( variables.verifier.getAllowedOrigins( { "allowedOrigins" : "not-an-array" } ) ).toBeEmpty();
			} );
		} );

		describe( "verify(): pulling headers off a ColdBox event", function(){
			/**
			 * Helper: a stub event whose getHTTPHeader() reads from the given struct and falls
			 * back to the caller-supplied default, just like the real request context.
			 */
			var buildMockEvent = function( required struct headerValues ){
				var stubValues = arguments.headerValues;
				var mockEvent  = createStub();
				mockEvent.$(
					method   = "getHTTPHeader",
					callback = function( required string header, string defaultValue = "" ){
						if ( structKeyExists( stubValues, arguments.header ) ) {
							return stubValues[ arguments.header ];
						}
						return arguments.defaultValue;
					}
				);
				return mockEvent;
			};

			it( "verifies against the forwarded host when trustUpstream is on", function(){
				var mockEvent = buildMockEvent( {
					"origin"           : "https://app.example.org",
					"x-forwarded-host" : "app.example.org, proxy.internal"
				} );
				var verdict = variables.verifier.verify(
					event  = mockEvent,
					config = { "enabled" : true, "trustUpstream" : true }
				);
				expect( verdict.allowed ).toBeTrue();
				expect( verdict.reason ).toBe( "origin-match" );
			} );

			it( "ignores X-Forwarded-Host when trustUpstream is off (fails closed to cgi.http_host)", function(){
				var mockEvent = buildMockEvent( {
					"origin"           : "https://app.example.org",
					"x-forwarded-host" : "app.example.org"
				} );
				var verdict = variables.verifier.verify(
					event  = mockEvent,
					config = { "enabled" : true, "trustUpstream" : false }
				);
				// cgi.http_host in the test runner is 127.0.0.1:60299, never app.example.org
				expect( verdict.allowed ).toBeFalse();
				expect( verdict.reason ).toBe( "origin-mismatch" );
			} );

			it( "lets Sec-Fetch-Site from the event drive the verdict", function(){
				var mockEvent = buildMockEvent( { "sec-fetch-site" : "cross-site" } );
				var verdict   = variables.verifier.verify( event = mockEvent, config = { "enabled" : true } );
				expect( verdict.allowed ).toBeFalse();
			} );
		} );
	}

}
