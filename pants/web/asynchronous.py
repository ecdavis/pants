###############################################################################
#
# Copyright 2011-2012 Pants Developers (see AUTHORS.txt)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
This is the asynchronous request helper for the Application system, utilizing
generator coroutines for optimal performance and ease of development.
"""

# Warning: This whole file is pretty much weird magic.

import json
import traceback
import weakref

from functools import wraps
from types import GeneratorType

from pants.http.utils import HTTPHeaders

from pants.web.application import Application, error, Response, RequestContext
from pants.web.utils import HTTPException, HTTPTransparentRedirect, log


###############################################################################
# Constants
###############################################################################

Again = object()
Waiting = object()
Finished = object()


###############################################################################
# Storage
###############################################################################

receivers = {}


###############################################################################
# Exceptions
###############################################################################

class TimeoutError(Exception):
    """
    Instances of TimeoutError are raised into an asynchronous request handler
    when an :func:`async.wait` or :func:`async.receieve` timeout.
    """
    pass


class RequestClosed(Exception):
    """
    An instance of RequestClosed is raised into an asynchronous request handler
    when the connection for the request is closed.
    """
    pass


###############################################################################
# Basic Asynchronous Requests
###############################################################################

def async(func):
    """
    The ``@async`` decorator is used in conjunction with
    :class:`pants.web.Application` to create asynchronous request handlers using
    generators. This is useful for performing database lookups and doing other
    I/O bound tasks without blocking the server. The following example performs
    a simple database lookup with a `fork <https://github.com/stendec/asyncmongo>`_
    of `asyncmongo <https://github.com/bitly/asyncmongo>`_ that adds support for
    Pants. It then uses `jinja2 <http://jinja.pocoo.org/>`_ templates to render
    the response.

    .. code-block:: python

        from pants.web import Application, async

        import jinja2
        import asyncmongo

        database_options = {
            'host': '127.0.0.1',
            'port': 27017,
            'dbname': 'test',
        }

        db = asyncmongo.Client(pool_id='web', backend='pants', **database_options)

        app = Application()
        env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"))

        index_template = env.get_template("index.html")

        @app.route("/")
        @async
        def index(request):
            results = yield async.run(db.news.find, {'published': True})
            yield index_template.render(data=results)

        app.run()

    Additionally, the @async decorator also allows for the easy implementation
    of server-sent events, including support for the ``text/event-stream``
    Content-Type used by HTML5 ```EventSource
    <http://dev.w3.org/html5/eventsource/>`_``.

    .. seealso::

        :func:`async.stream`, :func:`async.event_stream`
    """

    @wraps(func)
    def wrapper(request, *args, **kwargs):
        # Set a bit of state for the request.
        request._writer = _async_finish
        _init(request)

        # Create the generator.
        try:
            request._gen = gen = func(request, *args, **kwargs)
        except Exception:
            _cleanup(request)
            raise

        # If we've not got a generator, return the output.
        if not isinstance(gen, GeneratorType):
            _cleanup(request)
            return gen

        # Set a flag on the request so Application won't finish processing it.
        request.auto_finish = False

        # Now let's run the generator for the first time. No input yet, for
        # obvious reasons.
        _do(request, None)

    return wrapper


def _async_finish(request, output):
    """
    Write the provided output to the request and finish the request.
    """
    if request._started:
        request.connection.close(False)
        _cleanup(request)
        return

    # Do things App style.
    with request._context as app:
        request.auto_finish = True

        try:
            if output is Finished:
                raise RuntimeError("Reached StopIteration in asynchronous "
                                   "request handler.")

            app.parse_output(output)
        except Exception as err:
            if request._started:
                request.connection.close(False)
                _cleanup(request)
                return

            request._tb = traceback.format_exc()

            try:
                body, status, headers = app.handle_500(request, err)

            except Exception:
                log.exception("There was a problem handling an asynchronous "
                              "request, and a problem running "
                              "Application.handle_500 for %r." % app)
                body, status, headers = error(500, request=request)

            request.send_status(status)
            if not 'Content-Length' in headers:
                headers['Content-Length'] = len(body)
            request.send_headers(headers)
            request.write(body)
            request.finish()

    # Finish cleanup.
    _cleanup(request)


###############################################################################
# Asynchronous Streams
###############################################################################

def stream(func):
    """
    The ``@async.stream`` decorator is used to create asynchronous request
    handlers using generators. This can be used to begin writing a portion of
    the response to the client before the entire response can be generated.

    The very first yielded output is processed for a status code and headers
    using the same logic that :class:`~pants.web.Application` uses for its
    standard route functions.

    Subsequently yielded values are *not* processed, so returning a status code
    and/or headers in that situation will result in undesired output. You may
    return an instance of :class:`pants.web.Response` *or* the bare value to
    write out.

    The following is, though not particuarly useful, an example::

        @app.route("/")
        @async.stream
        def index(request):
            yield None, 200, {'X-Pizza': 'Yum'}
            yield "This is an example.\n"
            yield "It isn't particuarly useful.\n"

            yield ("This will be treated as a list and serialized with "
                   "JSON because you can't set the status code or provide "
                   "additional headers after the response has started."), 401

    """

    @wraps(func)
    def wrapped(request, *args, **kwargs):
        # Set a bit of state for the request.
        request._writer = _stream_output
        _init(request)

        # Create the generator.
        try:
            request._gen = gen = func(request, *args, **kwargs)
        except Exception:
            _cleanup(request)
            raise

        # If we've not got a generator, return the output.
        if not isinstance(gen, GeneratorType):
            _cleanup(request)
            return gen

        # Set a flag on the request so Application won't finish processing it.
        request.auto_finish = False

        # Now let's run the generator for the first time. No input yet, for
        # obvious reasons.
        _do(request, None)

    return wrapped

async.stream = stream


def _stream_output(request, output):
    """
    Write the provided chunk of data to the stream. This will automatically
    encode the output as Transfer-Encoding: chunked if necessary.
    """
    if request._started:
        if not output or output is Finished:
            # We're finished.
            if request._chunked:
                request.write("0\r\n\r\n\r\n")

            request.finish()
            _cleanup(request)
            return

        # Go ahead and cast the body and send it.
        if isinstance(output, Response):
            output = output.body

        try:
            output = _cast(request, output)
        except Exception:
            log.exception("Error casting output for asynchronous stream.")
            request.connection.close(False)
            _cleanup(request)
            return

        if request._chunked:
            request.write("%x\r\n%s\r\n" % (len(output), output))

        return Again


    # Assume that the first message has status and a header.
    if isinstance(output, Response):
        output, status, headers = output.body, output.status, output.headers
    elif isinstance(output, tuple):
        if len(output) == 3:
            output, status, headers = output
        else:
            output, status = output
            headers = HTTPHeaders()
    else:
        status = 200
        headers = HTTPHeaders()

    # Use the rule headers stuff.
    if request._rule_headers:
        if isinstance(request._rule_headers, HTTPHeaders):
            rule_headers = request._rule_headers.copy()
        else:
            rule_headers = HTTPHeaders(request._rule_headers)

        if isinstance(headers, HTTPHeaders):
            rule_headers._data.update(headers._data)
        else:
            rule_headers.update(headers)

        headers = rule_headers

    if request._rule_content_type and not 'Content-Type' in headers:
        headers['Content-Type'] = request._rule_content_type

    # Check for a character encoding.
    content_type = headers.get('Content-Type', '')
    if 'charset=' in content_type:
        request._charset = content_type.split('charset=',1)[1].strip()

    # Check the body to guess a Content-Type.
    if not 'Content-Type' in headers:
        if hasattr(output, "to_html") or (isinstance(output, basestring) and
                output[:5].lower() in ('<html', '<!doc')):
            headers['Content-Type'] = 'text/html; charset=%s' % request._charset
        elif isinstance(output, (tuple, list, dict)):
            headers['Content-Type'] = 'application/json'
        else:
            headers['Content-Type'] = 'text/plain; charset=%s' % request._charset

    # Finally, cast the body.
    errored = False
    if output is not None:
        try:
            output = _cast(request, output)
        except Exception as err:
            errored = True
            with request._context as app:
                try:
                    output, status, headers = app.handle_500(request, err)
                except Exception:
                    output, status, headers = error(500, request=request)

            if not 'Content-Length' in headers:
                headers['Content-Length'] = len(output)

    # Make sure the client has some way of determining the length.
    if not 'Content-Length' in headers and not 'Transfer-Encoding' in headers:
        headers['Transfer-Encoding'] = 'chunked'
        request._chunked = True

    # Now, send it all out.
    request.send_status(status)
    request.send_headers(headers)

    if request.method.upper() == 'HEAD':
        request.finish()
        _cleanup(request)
        return

    if output is not None:
        if request._chunked:
            request.write("%x\r\n%s\r\n" % (len(output), output))
        else:
            request.write(output)

    if errored:
        request.finish()
        _cleanup(request)
        return

    return Again


###############################################################################
# Event Stream
###############################################################################

def event_stream(func):
    """
    The ``@async.event_stream`` decorator allows you to easilly push server-sent
    events from Pants to your web clients using the new HTML5 `EventSource
    <http://dev.w3.org/html5/eventsource/>`_ API. Example::

        from pants.web import Application, async, TimeoutError

        @app.route("/events")
        @async.event_stream
        def events(request):
            try:
                message = yield async.receive("events", 10)
            except TimeoutError:
                yield None
            else:
                yield message

        # Elsewhere...

        async.send("events", "Something happened!")

    When you yield a value, there are a few ways it can be processed.

    1.  If the value is empty, None, etc. a single comment line will be sent to
        the client to keep the connection alive.

    2.  If the value is a tuple, it will be separated into ``(output, headers)``
        and the provided message headers will be prepended to the output before
        it's sent to the client.

    3.  Any other values for the output will result in normal output processing
        before the output is sent to the client as a message.

    .. note::

        ``@async.event_stream`` automatically formats output messages, handling
        line breaks for you.

    """

    @wraps(func)
    def wrapped(request, *args, **kwargs):
        # Set a bit of state for the request.
        request._writer = _event_stream_output
        _init(request)
        request._chunked = True

        # Create the generator.
        try:
            request._gen = gen = func(request, *args, **kwargs)
        except Exception:
            _cleanup(request)
            raise

        # If we've not got a generator, return the output.
        if not isinstance(gen, GeneratorType):
            _cleanup(request)
            return gen

        # Set a flag on the request so Application won't finish processing it.
        request.auto_finish = False

        # Now let's run the generator for the first time. No input yet, for
        # obvious reasons.
        _do(request, None)

    return wrapped

async.event_stream = event_stream


def _event_stream_output(request, output):
    """
    Write a text/event-stream message to the client. If no data has been sent
    yet, it writes a 200 OK response code and a Content-Type header.
    """
    if not request._started:
        request.send_status()
        request.send_headers({'Content-Type': 'text/event-stream'})

    if output is Finished:
        # We're finished.
        request.connection.close()
        _cleanup(request)
        return

    if isinstance(output, tuple):
        output, headers = output
    else:
        headers = {}

    if not output and not headers:
        # Send a simple comment line for keep-alive.
        request.write(":\r\n")
        return Again

    if output is None:
        output = ""
    else:
        # Cast the output into something usable.
        output = _cast(request, output)

    # Split up output, adding "data:" field names, and then prepend the
    # provided headers, if there are any.
    output = "\r\n".join("data: %s" % x for x in output.splitlines())
    for key, value in headers.iteritems():
        output = "%s: %s\r\n%s" % (key, _cast(request, value), output)

    # Write it out, with an extra blank line so that the client will read
    # the message.
    request.write("%s\r\n\r\n" % output)
    return Again


###############################################################################
# Asynchronous _Sleeper
###############################################################################

class _Sleeper(tuple):
    def __repr__(self):
        return "_Sleeper(%r)" % self[0]


def sleep(time):
    """
    Sleep for *time* seconds, doing nothing else during that period.
    """
    return _Sleeper((time,))

async.sleep = sleep


###############################################################################
# Asynchronous Caller
###############################################################################

def run(function, *args, **kwargs):
    """
    Run *function* with the provided *args* and *kwargs*.

    This works for any function that supports the ``callback`` keyword argument
    by inserting a callback object into the keyword arguments before calling
    the function.

    If you need to asynchronously call a function that *doesn't* use
    ``callback``, please use :func:`async.callback`.

    Here is a brief example using an `asyncmongo
    <https://github.com/bitly/asyncmongo>`_ Client named ``db``::

        @app.route("/count")
        @async
        def count(request):
            results = yield async.run(db.news.find, {'published': True})
            yield len(results)

    .. note::

        ``async.run`` does *not* process keyword arguments passed to the
        callback. If you require the keyword arguments, you must use
        :func:`async.callback` manually.

    Calling ``async.run`` returns the instance of
    :class:`pants.web.Callback` used. Yielding that instance will
    wait until the callback is triggered and return the value passed to
    the callback.
    """

    # Create a callback and set the callback keyword argument.
    kwargs['callback'] = cb = Callback()

    # Ignore the return value.
    function(*args, **kwargs)

    # Return the callback.
    return cb

async.run = run


class Callback(object):
    """
    Return an instance of :class:`pants.web.Callback` that can be used as a
    callback with other asynchronous code to capture output and return it to
    an asynchronous request handler.

    Yielding an instance of Callback will wait until the callback has been
    triggered, and then return values that were sent to the callback so that
    they may be used by the asynchronous request handler.

    It's easy::

        @app.route("/")
        @async
        def index(request):
            callback = async.callback()
            do_something_crazy(request, on_complete=callback)

            result = yield callback
            if not result:
                abort(403)

            yield result

    """

    __slots__ = ("request", "use_kwargs")

    def __init__(self, use_kwargs=False):
        # Store this callback.
        self.use_kwargs = use_kwargs
        self.request = request = Application.current_app.request
        request._callbacks[self] = Waiting
        request._unhandled.append(self)

    def __call__(self, *args, **kwargs):
        request = self.request
        if hasattr(request, "_callbacks"):
            if self.use_kwargs:
                args = (args, kwargs)
            elif len(args) == 1:
                args = args[0]

            request._callbacks[self] = args

            # Now, see if we're finished waiting.
            _check_waiting(request, self)

async.callback = Callback


###############################################################################
# Waiting
###############################################################################

class _WaitList(list):
    timeout = None


def wait(timeout=None):
    """
    Wait for all asynchronous callbacks to return, and return a list of those
    values. If a *timeout* is provide, wait up to that many seconds for the
    callbacks to return before raising a TimeoutError containing a list of
    the results that *did* complete.
    """
    request = Application.current_app.request
    top, request._unhandled = _WaitList(request._unhandled), []

    top.timeout = timeout
    return top

async.wait = wait


def _wait_timeout(request):
    """
    Handle a timed-out async.wait().
    """
    if not hasattr(request, "_in_do"):
        # Don't deal with requests that were closed. Just don't.
        return

    # Get the item off the top of the waiting stack, and make sure it's
    # something we can work with.
    if not request._waiting or not isinstance(request._waiting[-1], _WaitList):
        return

    # Build the input list.
    input = []
    for key in request._waiting.pop():
        value = request._callbacks.pop(key)
        input.append(value if value is not Waiting else None)

    # Now, pass it along to _do. Note the as_exception=True.
    _do(request, TimeoutError(input), as_exception=True)


def _check_waiting(request, trigger=None):
    """
    Check the waiting list for the provided request to determine if we should
    be taking action. If we should, pop the top item from the waiting list and
    send the input we've gathered into _do.
    """

    if not hasattr(request, "_in_do"):
        # If this happens, the request was *probably* closed. There's nothing
        # to do, so just get out of here.
        return

    # Get the item off the top of the waiting stack, and make sure it's
    # something we can work with.
    top = request._waiting[-1] if request._waiting else None

    if not isinstance(top, (_WaitList, Callback)):
        return

    # If a trigger was provided, check to see if the top *is* that trigger. If
    # this is the case, we can just return the result for that specific item.
    if top is trigger:
        # It is. We can pop off the top and send the input now.
        request._waiting.pop()
        _do(request, request._callbacks.pop(trigger))
        return

    # If we're still here, then we've got a list of callbacks to wait on. If
    # any of those are still Waiting, we're not done yet, so return early.
    if any(request._callbacks[key] is Waiting for key in top):
        return

    # Check the _WaitList's timeout, and clear it if we find one.
    if callable(top.timeout):
        top.timeout()

    # We're finished, so build the list and send it on to _do.
    input = [request._callbacks.pop(key) for key in request._waiting.pop()]
    _do(request, input)


###############################################################################
# Message Sending
###############################################################################

class _Receiver(tuple):
    timeout = None
    ref = None


def send(key, *args):
    """
    Send a message with the provided ``*args`` to all asynchronous requests
    listening for *key*.
    """

    # Get the list of requests listening for key. If there aren't any, return.
    recv = receivers.pop(key, None)
    if not recv:
        return

    # If we only have one argument, pop it out of its tuple.
    if len(args) == 1:
        args = args[0]

    # Now, for each listening request, make sure it's still alive before
    # sending the arguments its way.
    for ref in recv:
        request = ref()
        if not request:
            continue

        # Check for the _in_do attribute, to make sure the request is still
        # working asynchronously.
        if not hasattr(request, "_in_do"):
            continue

        # Get the top of the request's wait list and make sure it's what
        # we expect.
        if not request._waiting or not isinstance(request._waiting[-1], _Receiver):
            continue

        # Pop the top item off the wait list and clear any timeout.
        top = request._waiting.pop()
        if callable(top.timeout):
            top.timeout()

        # Now, send the message.
        _do(request, args)

async.send = send


def receive(key, timeout=None):
    """
    Listen for messages with the key *key*. If *timeout* is specified, wait
    up to that many seconds before raising a TimeoutError.
    """
    out = _Receiver((key, timeout))
    return out

async.receive = receive


def _receive_timeout(request):
    if not hasattr(request, "_in_do"):
        return

    # Make sure the top of the wait list is a _Receiver.
    if not request._waiting or not isinstance(request._waiting[-1], _Receiver):
        return

    # Remove this request from the receivers list so we don't get any
    # unexpected input later on.
    top = request._waiting.pop()

    if top[0] in receivers and top.ref in receivers[top[0]]:
        receivers[top[0]].remove(top.ref)

    # Now, send along a TimeoutError.
    _do(request, TimeoutError(), as_exception=True)


###############################################################################
# Asynchronous Internals
###############################################################################

def _init(request):
    """
    Set a bit of state for the request.
    """
    request._in_do = False
    request._chunked = False
    request._charset = "utf-8"
    request._tb = None
    request._callbacks = {}
    request._waiting = []
    request._unhandled = []

    # Create a RequestContext.
    request._context = RequestContext()


def _cast(request, output):
    """
    Convert an output object into something we can send over a connection.
    """
    if hasattr(output, "to_html"):
        output = output.to_html()

    if isinstance(output, (tuple, list, dict)):
        with request._context as app:
            return json.dumps(output, cls=app.json_encoder)

    elif isinstance(output, unicode):
        return output.encode(request._charset)

    elif not isinstance(output, str):
        with request._context:
            return str(output)

    return output


def _cleanup(request):
    """
    Delete the context manager and everything else.
    """

    del request._in_do
    del request._chunked
    del request._charset
    del request._unhandled

    del request._context

    try:
        del request._gen
    except AttributeError:
        del request._callbacks
        del request._waiting
        return

    # Cleanup any timers.
    for item in request._waiting:
        timer = getattr(item, "timeout", None)
        if timer and callable(timer):
            try:
                timer()
            except Exception:
                # Who knows what could happen here.
                pass

    # Asynchronous Internals
    request._callbacks.clear()
    del request._callbacks
    del request._waiting


def _do(request, input, as_exception=False):
    """
    Send the provided input to the asynchronous request handler for *request*.
    If ``as_exception`` is truthy, throw it into the generator as an exception,
    otherwise it's just sent.
    """
    if request._in_do:
        # Let's not enter some bizarre stack recursion that can cause all sorts
        # of badness today, shall we? Put off the next _do till the next
        # engine cycle.
        request.connection.engine.callback(_do, request, input, as_exception)
        return

    try:
        request._in_do = True

        while True:
            errored = False

            with request._context as app:
                # Make sure we're connected.
                if not request.connection.connected:
                    try:
                        # Bubble up an error so the user's code can do something
                        # about this.
                        request._gen.throw(RequestClosed())
                    except RequestClosed:
                        # Don't react at all to our own exception.
                        pass
                    except Exception:
                        # Just log any other exception. The request is already
                        # closed, so there's not a lot *else* to do.
                        log.exception("Error while cleaning up closed "
                                      "asynchronous request: %s %s" %
                                      (request.method, request.uri))
                    finally:
                        _cleanup(request)
                        return

                try:
                    if as_exception:
                        output = request._gen.throw(input)
                    else:
                        output = request._gen.send(input)

                except StopIteration:
                    # We've run out of content. Setting output to Finished
                    # tells the output handler to close up and go home.
                    output = Finished

                except HTTPException as err:
                    if request._started:
                        log.exception("Error while handling asynchronous "
                                      "request: %s %s" % (request.method,
                                                          request.uri))
                        request.connection.close(False)
                        _cleanup(request)
                        return

                    errored = True
                    request._tb = traceback.format_exc()

                    err_handler = getattr(app, "handle_%d" % err.status, None)
                    if err_handler:
                        output = err_handler(request, err)
                    else:
                        output = error(err.message, err.status, err.headers,
                            request=request)

                except HTTPTransparentRedirect as err:
                    if request._started:
                        log.exception("HTTPTransparentRedirect sent to already "
                                      "started request: %s %s" %
                                      (request.method, request.uri))
                        request.connection.close(False)
                        _cleanup(request)
                        return

                    errored = True
                    output = err
                    request._tb = traceback.format_exc()

                except Exception as err:
                    if request._started:
                        log.exception("Error while handling asynchronous "
                                      "request: %s %s" % (request.method,
                                                          request.uri))
                        request.connection.close(False)
                        _cleanup(request)
                        return

                    errored = True
                    request._tb = traceback.format_exc()

                    try:
                        output = app.handle_500(request, err)
                    except Exception:
                        # There's an error with the handle_500 function.
                        log.exception("There was a problem handling a request, and a "
                                      "problem running Application.handle_500 for %r."
                                        % app)

                        output = error(500, request=request)

            # Did we error?
            if errored:
                # Clear the rule data, because errors don't care about it.
                request._rule_content_type = None
                request._rule_headers = None

                _async_finish(request, output)
                return

            # Returning a list of Callback instances is the only way to control
            # exactly what you're waiting for.
            if not isinstance(output, _WaitList) and \
                    isinstance(output, (tuple, list)) and \
                    all(isinstance(x, Callback) for x in output):
                output = _WaitList(output)

            # Now that we're out of the request context, let's see what we've got to
            # work with.
            if isinstance(output, _Sleeper):
                # Just sleep.
                request.connection.engine.defer(output[0], _do, request, None)

            elif isinstance(output, Callback):
                # Shove the callback onto its own waiting list.
                request._unhandled.remove(output)
                request._waiting.append(output)

            elif isinstance(output, _WaitList):
                # Push the WaitList onto the waiting list.
                if output.timeout:
                    output.timeout = request.connection.engine.defer(output.timeout, _wait_timeout, request)
                request._waiting.append(output)

            elif isinstance(output, _Receiver):
                # Push the Receiver onto the waiting list.
                if output[1]:
                    output.timeout = request.connection.engine.defer(output[1], _receive_timeout, request)

                output.ref = ref = weakref.ref(request)
                receivers.setdefault(output[0], []).append(ref)
                request._waiting.append(output)

            else:
                # We've received some content, so write it out.
                if request._writer(request, output) is Again:
                    input = None
                    as_exception = False
                    continue

            # We *have* to continue if we don't want to break.
            break

    finally:
        if hasattr(request, "_in_do"):
            request._in_do = False
