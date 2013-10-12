Changelog
=========

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
 *  *Added* ``pants.web.async``, a decorator for use with Application that
            uses generators to make asynchronous request handling easy.

 *  *Added* unit tests for HTTPRequest's secure cookies.
 
 *  *Added* support for JSON and unicode values to HTTPRequest's
            secure cookies.
 
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

 *  *Added* the ``pants.web.Response`` class as a potential return value for
            Application route handlers.

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

 *  *Added* ``headers`` and ``content_type`` arguments to Application's
            ``route`` and ``basic_route`` decorators. 

 *  *Added* support for route variables to WebSockets attached to Application
            instances. They are handled in the ``on_connect`` function.

 *  *Fixed* ``Application.route``'s handling of route handlers, removing the
            inspection of function arguments and making it always pass the
            ``request`` argument, leading to a more predictable experience.

 *  *Added* checks to ``pants.web.Module`` against cyclic nesting of Modules.

 *  *Fixed* the routing table generation in Application to eliminate
            rule collisions.

1.0.0-beta.1 (2012-10-21)
-------------------------
 * Initial preview release