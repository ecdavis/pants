Changelog
=========

1.0.0 (current)
---------------
 *  *Removed* Pants' DNS utility. UDP support needs to be completely rewritten
            before it can be released properly.

 *  *Changed* ``FileServer`` to use the new ``HTTPRequest.send_file`` method.
            This required the removal of the experimental renderers and
            greatly simplified the code.

 *  *Changed* ``HTTPRequest.uri`` to ``HTTPRequest.url`` and otherwise changed
            all uses of URI to URL for consistency.

 *  *Changed* ``url_for``'s name processing behavior to be more intuitive.

 *  *Changed* ``WebSocket`` to clearly differentiate between byte strings and
            unicode strings and added support for fragmented messages.

 *  *Changed* the HTTP client API to bring it more in line with that of the
            excellent requests module.

 *  *Fixed* a bug in ``_Channel.close`` which could cause an AttributeError to
            be raised if the socket was None.

 *  *Fixed* a bug in ``sendfile`` on Mac OS X which caused Pants to resend the
            same bytes repeatedly.

 *  *Fixed* Server such that ``on_close`` is actually called when the server is
            closed.

 *  *Fixed* ``Application``'s handling of HTTP status codes that should not
            have response bodies. Application will now generate
            ``204 No Content`` responses if a route handler returns None.

 *  *Fixed* ``WSGIConnector`` and ``FileServer`` not correctly handling it when
            ``Application`` passes more than one variable captured from
            the URL.

 *  *Fixed* ``HTTPRequest`` using the imprecise ``time.time`` on Windows rather
            than ``time.clock``.

 *  *Fixed* ``Application.run`` not actually using the provided ``Engine``
            instance when creating its internal ``HTTPServer`` instance.

 *  *Fixed* bug in ``WebSocket.write_file`` causing it to believe that the
            WebSockets were always disconnected.

 *  *Fixed* bug in ``WebSocket`` causing it to only handle one incoming message
            when more than one message was received within a single read event.
            Also added checks to prevent the buffer from expanding beyond the
            maximum allowed size.

 *  *Added* ``HTTPRequest.send_file`` for sending static files to the client in
            the most efficient way possible.

 *  *Added* basic hooks to ``Application`` for when requests are started,
            finished, and torn down.

 *  *Added* advanced ``Converter`` support for capturing variables from URLs
            with Application. Converters are now classes, and capable of
            using custom regular expressions with any number of capture groups
            to capture their data.

 *  *Added* optional request parameters to various ``pants.web.application``.

 *  *Added* ``WebSocket.ping`` and an associated ``on_pong`` event handler.

 *  *Added* ``HTTPRequest.is_secure`` property for easily determining whether
            or not the request was received via HTTPS.


1.0.0-beta.3 (2013-03-25)
-------------------------
 *  *Changed* ``engine.time`` to ``engine.latest_poll_time``, as that name more
              accurately reflects the value of the attribute.

 *  *Fixed* a bug in Stream that would cause buffered data to be lost when the
            Stream was closed. Streams now process buffered data before closing
            to make sure all data is passed to ``on_read``.

 *  *Fixed* automatic address family detection, notably fixing a bug that would
            prevent Pants from connecting to IPv6 addresses unless given an
            address tuple with four entries.

 *  *Fixed* a bug in ``pants.web`` preventing it from being successfully
            imported in Python 2.6.

 *  *Added* Windows-specific timing code to improve the precision of timer
            execution on Windows platforms.

 *  *Added* the ability to create a basic HTTP file server by running the
            ``pants.web.fileserver`` module using:
            ``python -m pants.web.fileserver``

 *  *Added* support for using [NetStruct](https://github.com/stendec/netstruct)
            instances as ``read_delimiters``.


1.0.0-beta.2 (2012-11-05)
-------------------------
 *  *Fixed* HTTPRequest's secure cookies not being HttpOnly by default.
 
 *  *Fixed* a bug in HTTPRequest's secure cookies that would cause an exception
            when trying to read a non-existent cookie, rather than returning
            None.

 *  *Fixed* the use of structs as read_delimiters everywhere, removing the
            ``struct_delimiter`` class and using instead ``struct.Struct``.

 *  *Fixed* a bug in Application's default 500 error handler that would result
            in a non-pretty error page when debugging is disabled, and made
            errors within the core Application generate appropriately pretty
            error pages as well.

 *  *Fixed* HTTP header handling with a new data structure that has
            improved random access performance and iteration that, while
            slower, is guaranteed to produce proper HTTP header casing.

 *  *Fixed* HTTPRequest's ``scheme`` and ``protocol`` variables were misnamed.
            ``scheme`` is the URI scheme (either 'http' or 'https') and
            ``protocol`` is the HTTP protocol version.

 *  *Fixed* HTTPException and HTTPTransparentRedirect now call ``super()``.

 *  *Fixed* Application's support resource loading now uses ``pkg_resources``
            rather than ``__file__``.

 *  *Fixed* FileServer not checking file permissions before attempting to read
            a file and not handling the resulting exception.

 *  *Fixed* ``Application.route``'s handling of route handlers, removing the
            inspection of function arguments and making it always pass the
            ``request`` argument, leading to a more predictable experience.

 *  *Fixed* the routing table generation in Application to eliminate
            rule collisions.

 *  *Added* ``pants.web.async``, a decorator for use with Application that
            uses generators to make asynchronous request handling easy.

 *  *Added* unit tests for HTTPRequest's secure cookies.

 *  *Added* support for JSON and unicode values to HTTPRequest's
            secure cookies.

 *  *Added* the ``pants.web.Response`` class as a potential return value for
            Application route handlers.

 *  *Added* ``headers`` and ``content_type`` arguments to Application's
            ``route`` and ``basic_route`` decorators. 

 *  *Added* support for route variables to WebSockets attached to Application
            instances. They are handled in the ``on_connect`` function.

 *  *Added* checks to ``pants.web.Module`` against cyclic nesting of Modules.


1.0.0-beta.1 (2012-10-21)
-------------------------
 * Initial preview release