/**
 * MethodGuardTest
 *
 * The load-bearing spec of the whole de-spoofer, and the reason isSpoofed() is public.
 *
 * Under TestBox, `cgi.request_method` is ALWAYS "GET" and no BaseTestCase helper can change it. So
 * the integration bundle can only ever reproduce the ATTACK -- it physically cannot reproduce the
 * LEGITIMATE case, a real browser POST carrying `_method=DELETE`, which is how every Delete button in
 * every consuming app submits.
 *
 * Which means: if the transport check in isSpoofed() were ever inverted, OriginGuard would strip
 * `_method` from every legitimate POST, every Delete button in every consuming app would break in a
 * real browser, and the entire CFML suite would stay green. That is the worst failure shape there is.
 * The matrix below is the only thing standing between us and it.
 *
 * MethodGuard injects nothing, so we can `new` it outright -- no ColdBox, no WireBox. Every call uses
 * named arguments (the Lucee positional-argument tripwire in AGENTS.md).
 *
 * TEMPORARY: delete this bundle with the rest of the shim when COLDBOX-1406 ships.
 */
component extends="testbox.system.BaseSpec" {

	function beforeAll(){
		variables.guard = new originguard.interceptors.MethodGuard();
	}

	/**
	 * Helper: is this transport/declared pair a spoof?
	 *
	 * @transport The verb the request actually arrived on.
	 * @declared  The `_method` value riding in the request collection.
	 */
	private boolean function isSpoof( required string transport, required string declared ){
		return variables.guard.isSpoofed(
			transportMethod = arguments.transport,
			declaredMethod  = arguments.declared
		);
	}

	function run(){
		describe( "An UNSAFE transport: the legitimate form-spoofing path", function(){
			it( "leaves POST -> DELETE alone (BREAK THIS AND EVERY DELETE BUTTON BREAKS)", function(){
				expect( isSpoof( transport = "POST", declared = "DELETE" ) ).toBeFalse();
			} );

			it( "leaves POST -> PUT alone", function(){
				expect( isSpoof( transport = "POST", declared = "PUT" ) ).toBeFalse();
			} );

			it( "leaves POST -> PATCH alone", function(){
				expect( isSpoof( transport = "POST", declared = "PATCH" ) ).toBeFalse();
			} );

			it( "leaves an unsafe transport with no claim alone", function(){
				expect( isSpoof( transport = "POST", declared = "" ) ).toBeFalse();
			} );

			it( "leaves the POST -> GET downgrade alone: that is the ORIGIN gate's job, not ours", function(){
				// Stripping here would be pointless. A declared GET can only make allowedMethods
				// STRICTER, so it cannot reach a mutation. What it CAN do is make a hostile
				// cross-origin POST look safe -- which is why OriginFirewall gates on the raw
				// cgi.request_method and never on getHTTPMethod() alone.
				expect( isSpoof( transport = "POST", declared = "GET" ) ).toBeFalse();
			} );

			it( "leaves a real DELETE that redundantly declares DELETE alone", function(){
				expect( isSpoof( transport = "DELETE", declared = "DELETE" ) ).toBeFalse();
			} );
		} );

		describe( "A SAFE transport claiming an unsafe verb: the drive-by attack", function(){
			it( "catches the <img src> GET -> DELETE", function(){
				expect( isSpoof( transport = "GET", declared = "DELETE" ) ).toBeTrue();
			} );

			it( "catches GET -> POST", function(){
				expect( isSpoof( transport = "GET", declared = "POST" ) ).toBeTrue();
			} );

			it( "catches HEAD -> PUT", function(){
				expect( isSpoof( transport = "HEAD", declared = "PUT" ) ).toBeTrue();
			} );

			it( "catches OPTIONS -> DELETE", function(){
				expect( isSpoof( transport = "OPTIONS", declared = "DELETE" ) ).toBeTrue();
			} );

			it( "is case-insensitive", function(){
				expect( isSpoof( transport = "get", declared = "delete" ) ).toBeTrue();
			} );

			it( "trims whitespace, so padding cannot smuggle a verb past it", function(){
				expect( isSpoof( transport = " GET ", declared = " DELETE " ) ).toBeTrue();
			} );
		} );

		describe( "A SAFE transport with nothing to hide", function(){
			it( "ignores an absent claim", function(){
				expect( isSpoof( transport = "GET", declared = "" ) ).toBeFalse();
			} );

			it( "ignores a blank claim: a client that disables the field still posts an empty value", function(){
				expect( isSpoof( transport = "GET", declared = "   " ) ).toBeFalse();
			} );

			it( "ignores a safe claim on a safe transport", function(){
				expect( isSpoof( transport = "GET", declared = "GET" ) ).toBeFalse();
			} );

			it( "ignores a safe claim of a DIFFERENT safe verb", function(){
				expect( isSpoof( transport = "GET", declared = "HEAD" ) ).toBeFalse();
			} );
		} );
	}

}
