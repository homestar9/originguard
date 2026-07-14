/**
 * A fixture error renderer. Proves two firewall behaviors: events matching ":errors." are
 * never intercepted, and a host can point denialEvent at its own handler.
 */
component {

	/**
	 * A consumer-style custom denial page.
	 *
	 * @event The request context.
	 * @rc    The request collection.
	 * @prc   The private request collection.
	 */
	function onOriginFailure( event, rc, prc ){
		arguments.event.renderData(
			type       = "html",
			data       = "guinea custom denial",
			statusCode = 403,
			statusText = "Forbidden"
		);
	}

}
