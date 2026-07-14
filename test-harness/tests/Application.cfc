/**
 * Copyright 2005-2007 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 */
component {

	// The name of the module used in cfmappings ,etc
	request.MODULE_NAME = "originguard";
	// The directory name of the module on disk. Usually, it's the same as the module name
	request.MODULE_PATH = "originguard";

	// APPLICATION CFC PROPERTIES
	this.name                 = "#request.MODULE_NAME# Testing Suite";
	this.sessionManagement    = true;
	this.sessionTimeout       = createTimespan( 0, 0, 15, 0 );
	this.applicationTimeout   = createTimespan( 0, 0, 15, 0 );
	this.setClientCookies     = true;
	// Turn on/off white space management
	this.whiteSpaceManagement = "smart";
	this.enableNullSupport    = shouldEnableFullNullSupport();

	// Create testing mapping
	this.mappings[ "/tests" ] = getDirectoryFromPath( getCurrentTemplatePath() );

	// The application root
	rootPath                 = reReplaceNoCase( this.mappings[ "/tests" ], "tests(\\|/)", "" );
	this.mappings[ "/root" ] = rootPath;

	// The module root path
	moduleRootPath = reReplaceNoCase(
		rootPath,
		"#request.MODULE_PATH#(\\|/)test-harness(\\|/)",
		""
	);
	this.mappings[ "/moduleroot" ]            = moduleRootPath;
	this.mappings[ "/#request.MODULE_NAME#" ] = moduleRootPath & "#request.MODULE_PATH#";

	function onRequestStart( required targetPage ){
		// Set a high timeout for long running tests
		setting requestTimeout   ="9999";
		// New ColdBox Virtual Application Starter
		request.coldBoxVirtualApp= new coldbox.system.testing.VirtualApp( appMapping = "/root" );

		// If hitting the runner or specs, prep our virtual app
		if ( getBaseTemplatePath().replace( expandPath( "/tests" ), "" ).reFindNoCase( "(runner|specs)" ) ) {
			request.coldBoxVirtualApp.startup( true );
		}

		if ( structKeyExists( url, "fwreinit" ) ) {
			if ( structKeyExists( server, "lucee" ) ) {
				pagePoolClear();
			}
			request.coldBoxVirtualApp.restart();
		}

		return true;
	}

	public void function onRequestEnd( required targetPage ){
		if ( request.keyExists( "coldBoxVirtualApp" ) ) {
			request.coldBoxVirtualApp.shutdown();
		}
	}

	private boolean function shouldEnableFullNullSupport(){
		var system = createObject( "java", "java.lang.System" );
		var value  = system.getEnv( "FULL_NULL" );
		return isNull( value ) ? false : !!value;
	}

}
