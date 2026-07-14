/**
 * Errors
 *
 * The default denial renderer for blocked cross-origin requests. Deliberately tiny and
 * self-contained: no views, no layouts, no prc dependencies, so it can render safely for any
 * host application. Real consumers usually point `denialEvent` at their own handler instead.
 */
component {

	/**
	 * Answer a blocked request with a 403. JSON for AJAX callers, a minimal HTML page
	 * otherwise. Note: isAjax() keys off X-Requested-With, which cross-site fetch() never
	 * sends, so most real attack denials take the HTML branch. That is fine for a default.
	 *
	 * @event The request context.
	 * @rc    The request collection.
	 * @prc   The private request collection.
	 */
	function onBlocked( event, rc, prc ){
		var blockReason = "";
		if ( structKeyExists( arguments.prc, "originBlockReason" ) ) {
			blockReason = arguments.prc.originBlockReason;
		}

		if ( arguments.event.isAjax() ) {
			arguments.event.renderData(
				type = "json",
				data = {
					"error"    : true,
					"code"     : "origin",
					"messages" : [ "This request was blocked because it did not come from an allowed origin." ],
					"data"     : { "reason" : blockReason }
				},
				statusCode = 403,
				statusText = "Forbidden"
			);
			return;
		}

		var page = "<!DOCTYPE html>
			<html lang=""en"">
			<head><meta charset=""utf-8""><title>Request Blocked</title></head>
			<body style=""font-family: sans-serif; max-width: 40em; margin: 4em auto;"">
				<h1>Request Blocked</h1>
				<p>
					This request was blocked because it did not come from an allowed origin.
					If you believe this is a mistake, go back, reload the page, and try again.
				</p>
			</body>
			</html>";

		arguments.event.renderData(
			type       = "html",
			data       = page,
			statusCode = 403,
			statusText = "Forbidden"
		);
	}

}
