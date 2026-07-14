/**
 * Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 */
component {

	// Module Properties
	this.title       = "OriginGuard";
	this.author      = "David Levin";
	this.webURL      = "https://github.com/homestar9/originguard";
	this.description = "Header-based cross-origin (CSRF) protection using the browser's Sec-Fetch-Site and Origin headers. No tokens, no sessions.";
	this.version     = "@build.version@+@build.number@";

	// Model Namespace
	this.modelNamespace = "originguard";

	// CF Mapping
	this.cfmapping = "originguard";

	// Dependencies
	this.dependencies = [];

	/**
	 * Configure Module
	 */
	function configure(){
		settings = {};
	}

	/**
	 * Fired when the module is registered and activated.
	 */
	function onLoad(){
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

}
