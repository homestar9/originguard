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
			// A TEMPORARY SHIM for a ColdBox bug (COLDBOX-1406): getHTTPMethod() trusts a spoofable
			// `_method` key, so a cross-site <img src="...?_method=DELETE"> is a GET that
			// this.allowedMethods waves through as a DELETE. MethodGuard strips the forged key.
			//
			// It reads NO settings and is not scoped: `enabled`, `secureList` and `mode` turn off the
			// ORIGIN check, never this. A GET-reachable delete is a bug, not a policy.
			//
			// It is registered first so a stripped request reaches OriginFirewall already honest, but
			// the order is not safety-critical: run OriginFirewall first and it would simply reject the
			// same cross-site request as a DELETE. Either order ends inert, so the order only decides
			// whether the attacker gets a 405 or a 403.
			//
			// DELETE THIS ENTRY when COLDBOX-1406 ships. See interceptors/MethodGuard.cfc.
			{
				class : "originguard.interceptors.MethodGuard",
				name  : "MethodGuard"
			},
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
