/**
 * The protected fixture handler the integration specs POST against.
 */
component {

	/**
	 * A verb-locked action, so MethodGuardTest can prove the whole chain: strip the forged `_method`,
	 * let ColdBox's own allowedMethods check see the honest GET, and answer 405 instead of deleting.
	 *
	 * This is the exact shape of a real consumer's Delete button, and the exact shape of the
	 * <img src="...?_method=DELETE"> attack that shape is vulnerable to.
	 */
	this.allowedMethods = { "destroy" : "DELETE" };

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

	/**
	 * The DELETE-only action the drive-by attack aims at. It must never run on a GET.
	 *
	 * @event The request context.
	 * @rc    The request collection.
	 * @prc   The private request collection.
	 */
	function destroy( event, rc, prc ){
		arguments.event.renderData( type = "html", data = "guinea destroyed" );
	}

	/**
	 * Without this, a rejected verb makes ColdBox THROW InvalidHTTPMethod rather than answer a 405,
	 * and the spec would blow up instead of asserting the outcome. A real consumer wants this too.
	 *
	 * @event          The request context.
	 * @rc             The request collection.
	 * @prc            The private request collection.
	 * @faultAction    The action whose verb lock rejected the request.
	 * @eventArguments Any arguments passed to the event.
	 */
	function onInvalidHTTPMethod(
		event,
		rc,
		prc,
		faultAction,
		eventArguments
	){
		arguments.event.renderData(
			type       = "html",
			data       = "guinea 405",
			statusCode = 405,
			statusText = "Method Not Allowed"
		);
	}

}
