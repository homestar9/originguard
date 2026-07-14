/**
 * Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 */
component {

	// Module Properties
	this.title       = "OriginGuard";
	this.author      = "Angry Sam Productions, Inc.";
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
		variables.settings = {
			// Master switch. OFF means ZERO cross-origin protection from this module.
			enabled        : true,
			// Trusted cross-origin callers. "partner.com" trusts both schemes;
			// "https://partner.com" pins the scheme (recommended). Empty = own host only.
			allowedOrigins : [],
			// Honour X-Forwarded-Host (only turn on behind a Host-rewriting reverse proxy).
			trustUpstream  : false,
			// Firewall: which events to protect. A comma list (or array) of case-insensitive
			// regex patterns, matched with an UNANCHORED find, so anchor with "^". The single
			// token "*" is an alias for "every event". Empty = the firewall is off entirely,
			// which is how a service-mode-only consumer opts out.
			secureList     : "*",
			// Firewall: carve-outs from secureList, e.g. "^checkout:webhook\.". Same pattern
			// syntax. A whiteList hit always wins.
			whiteList      : "",
			// Firewall: HTTP verbs that never need a check.
			safeMethods    : "GET,HEAD,OPTIONS",
			// Firewall: "block" enforces; "monitor" only logs what WOULD be blocked.
			// Roll out safely: monitor first, watch the logs, then switch to block.
			mode           : "block",
			// Firewall: where a blocked request lands. Point this at your own handler
			// to render a custom denial page.
			denialEvent    : "originguard:errors.onBlocked"
		};

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
