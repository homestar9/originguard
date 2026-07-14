# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

----

## [Unreleased]

## [1.0.0] => 2026-JUL-14

Initial release.

### Added

* `OriginVerifier@originguard`, a pure, stateless service for header-based cross-origin request
  verification. It uses `Sec-Fetch-Site` when available and falls back to `Origin` or `Referer`.
* `OriginFirewall`, a turnkey interceptor that protects unsafe requests by default. Protection can
  be scoped to ColdBox events with `secureList` and `whiteList` patterns.
* Block and monitor modes, trusted-origin allowlisting, reverse-proxy support, configurable safe
  methods, and a customizable denial event.
* A self-contained default 403 response, including JSON output for AJAX requests.
* `MethodGuard`, a temporary workaround for ColdBox issue
  [COLDBOX-1406](https://ortussolutions.atlassian.net/browse/COLDBOX-1406), which prevents a safe HTTP
  request from using a forged `_method` value to reach an unsafe handler action.
* Support for Lucee 5+, Adobe ColdFusion 2023+, and BoxLang 1+ through its CFML compatibility layer.
