/**
 * A second fixture handler inside the guinea module. Its only job is to give the whiteList
 * pattern specs something to discriminate against: a spec can carve out this ONE action
 * ("^guinea:api\.webhook$") and still prove guinea:main.save stays protected.
 */
component {

	/**
	 * A pretend third-party webhook - the classic reason a real app needs a whiteList entry,
	 * since a payment gateway posts here cross-site on purpose.
	 *
	 * @event The request context.
	 * @rc    The request collection.
	 * @prc   The private request collection.
	 */
	function webhook( event, rc, prc ){
		arguments.event.renderData( type = "html", data = "guinea webhook" );
	}

}
