/**
 * The protected fixture handler the integration specs POST against.
 */
component {

	/**
	 * A pretend state-changing action. If the firewall lets the request through, this renders.
	 *
	 * @event The request context.
	 * @rc    The request collection.
	 * @prc   The private request collection.
	 */
	function save( event, rc, prc ){
		arguments.event.renderData( type = "html", data = "guinea saved" );
	}

}
