/**
 * ModuleSpec
 *
 * Proves the module actually registers and wires inside a running ColdBox app. The heavy
 * behavioral coverage lives in the unit and integration specs; this is the canary that the
 * module itself loads.
 */
component extends="coldbox.system.testing.BaseTestCase" appMapping="root" {

	function run(){
		describe( "OriginGuard module", function(){
			beforeEach( function( currentSpec ){
				setup();
			} );

			it( "registers and activates in the host application", function(){
				expect( getController().getModuleService().isModuleActive( "originguard" ) ).toBeTrue();
			} );

			it( "wires the verifier through the module namespace", function(){
				expect( getInstance( "OriginVerifier@originguard" ) ).toBeInstanceOf( "OriginVerifier" );
			} );
		} );
	}

}
