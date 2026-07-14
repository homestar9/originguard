/**
 * A root-app error renderer fixture. Proves the firewall's errors exemption also covers
 * handlers with no module prefix (a root app protected via the "*" or "/" tokens must still
 * be able to render its own error pages).
 */
component {

	/**
	 * A pretend root-app error page.
	 *
	 * @event The request context.
	 * @rc    The request collection.
	 * @prc   The private request collection.
	 */
	function onOops( event, rc, prc ){
		arguments.event.renderData( type = "html", data = "root error page" );
	}

}
