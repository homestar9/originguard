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
		settings = {
			// Master switch. OFF means ZERO cross-origin protection from this module.
			enabled          : true,
			// Trusted cross-origin callers (host[:port], scheme ignored). Empty = own host only.
			allowedOrigins   : [],
			// Honour X-Forwarded-Host (only turn on behind a Host-rewriting reverse proxy).
			trustUpstream    : false,
			// Interceptor mode: module prefixes whose unsafe events get checked. Empty = the
			// interceptor does nothing, which is the safe default for service-mode consumers.
			protectedModules : [],
			// Interceptor mode: HTTP verbs that never need a check.
			safeMethods      : "GET,HEAD,OPTIONS",
			// Interceptor mode: where a blocked request lands. Point this at your own handler
			// to render a custom denial page.
			denialEvent      : "originguard:errors.onBlocked"
		};

		// Always registered; it no-ops instantly unless protectedModules is configured.
		// ColdBox appends "@originguard" to the name, so the final registered name is
		// "OriginFirewall@originguard".
		interceptors = [
			{
				class : "originguard.interceptors.OriginFirewall",
				name  : "OriginFirewall"
			}
		];
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
