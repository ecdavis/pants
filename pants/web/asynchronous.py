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

from pants.http.utils import HTTPHeaders

from pants.web.application import Application, error, Response, RequestContext
from pants.web.utils import HTTPException, HTTPTransparentRedirect, log


###############################################################################
# Constants
###############################################################################

Again = object()
Waiting = object()
Finished = object()

receivers = {}

###############################################################################
# Exceptions
###############################################################################

class TimeoutError(Exception):
    pass


class RequestClosed(Exception):
    pass


###############################################################################
# Basic Asynchronous Requests
###############################################################################

def async(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        # Set a bit of state for the request.
        request._writer = _finish
        _init(request)

        # Create the generator.
        try:
            request._gen = func(request, *args, **kwargs)
        except Exception:
            _cleanup(request)
            raise

        # Now let's run the generator for the first time. No input yet, for
        # obvious reasons.
        _do(request, None)

    return wrapper


def _finish(request, output, errored):
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
    @wraps(func)
    def wrapped(request, *args, **kwargs):
        # Set a bit of state for the request.
        request._writer = _stream
        _init(request)

        # Create the generator.
        try:
            request._gen = func(request, *args, **kwargs)
        except Exception:
            _cleanup(request)
            raise

        # Now let's run the generator for the first time. No input yet, for
        # obvious reasons.
        _do(request, None)

    return wrapped

async.stream = stream


def _stream(request, output, errored):
    """
    Write the provided chunk of data to the stream.
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

    if request._chunked:
        request.write("%x\r\n%s\r\n" % (len(output), output))
    else:
        request.write(output)

    if errored:
        request.finish()
        _cleanup(request)
        return

    return Again


def _cast(request, output):
    """
    Convert the output into something usable.
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


###############################################################################
# Event Stream
###############################################################################

def event_stream(func):
    @wraps(func)
    def wrapped(request, *args, **kwargs):
        # Set a bit of state for the request.
        request._writer = _event_stream
        _init(request)
        request._chunked = True

        # Create the generator.
        try:
            request._gen = func(request, *args, **kwargs)
        except Exception:
            _cleanup(request)
            raise

        # Now let's run the generator for the first time. No input yet, for
        # obvious reasons.
        _do(request, None)

    return wrapped

async.event_stream = event_stream


def _event_stream(request, output, errored):
    """
    Write out an event stream message to the client.
    """
    if not request._started:
        request.send_status()
        request.send_headers({'Content-Type': 'text/event-stream'})

    if not output or output is Finished:
        # We're finished.
        request.connection.close()
        _cleanup(request)
        return

    if isinstance(output, tuple):
        output, headers = output
    else:
        headers = {}

    # Cast the output into something usable.
    output = _cast(request, output)

    output = "\r\n".join("data: %s" % x for x in output.splitlines())
    for key, value in headers.iteritems():
        output = "%s: %s\r\n%s" % (key, _cast(request, value), output)

    request.write("%s\r\n\r\n" % output)
    return Again


###############################################################################
# Asynchronous Sleeper
###############################################################################

class Sleeper(tuple):
    def __repr__(self):
        return "Sleeper(%r)" % self[0]


def sleep(time):
    """
    Sleep for *time* seconds.
    """
    return Sleeper((time,))

async.sleep = sleep


###############################################################################
# Asynchronous Caller
###############################################################################

def run(func, *args, **kwargs):
    # Create a callback.
    cb = Callback()
    kwargs['callback'] = cb

    # Ignore the return value.
    func(*args, **kwargs)

    # Return the callback.
    return cb

async.run = run


class Callback(object):
    __slots__ = ("request")

    def __init__(self):
        # Store this callback.
        self.request = request = Application.current_app.request
        request._callbacks[self] = Waiting
        request._unhandled.append(self)

    def __call__(self, *args, **kwargs):
        request = self.request
        if hasattr(request, "_callbacks"):
            request._callbacks[self] = args[0] if len(args) == 1 else args

            # Now, see if we're finished waiting.
            _waiting(request, self)

async.callback = Callback


###############################################################################
# Waiting
###############################################################################

def _waiting(request, trigger):
    # Check the top of the stack to see if we're done waiting.
    if not hasattr(request, "_in_do"):
        return
    elif request._in_do:
        request.connection.engine.callback(_waiting, request, trigger)
        return

    # Make sure we're dealing with the right thing.
    if not request._waiting or not isinstance(request._waiting[-1],
                                                (_WaitList, Callback)):
        return

    top = request._waiting[-1]
    if top is trigger:
        # Just the one thing.
        request._waiting.pop()
        input = request._callbacks.pop(trigger)
        _do(request, input)
        return

    # Iterate the whole thing to see if we're needed.
    for cb in top:
        if request._callbacks[cb] is Waiting:
            return

    # Cancel the timeout if there is one.
    if top.timeout and callable(top.timeout):
        top.timeout()

    # Here? We have what we need then.
    input = [request._callbacks.pop(key) for key in request._waiting.pop()]
    _do(request, input)


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
    if not hasattr(request, "_in_do"):
        return
    elif request._in_do:
        request.connection.engine.callback(_wait_timeout, request)
        return

    # Make sure we've got the right thing.
    if not request._waiting or not isinstance(request._waiting[-1], _WaitList):
        return

    # Build a list of everything.
    input = []
    for key in request._waiting.pop():
        value = request._callbacks.pop(key)
        input.append(value if value is not Waiting else None)

    _do(request, TimeoutError(input), True)


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
    recv = receivers.pop(key, None)
    if not recv:
        return

    if len(args) == 1:
        args = args[0]

    for ref in recv:
        o = ref()
        if not o:
            continue

        # Clear the timeout for the object.
        if not hasattr(o, "_waiting") or not o._waiting or \
                not isinstance(o._waiting[-1], _Receiver):
            continue

        top = o._waiting.pop()
        if top.timeout:
            top.timeout()

        # Send the message.
        if getattr(o, "_in_do", None):
            o.connection.engine.callback(_do, o, args)
        else:
            _do(o, args)

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
    elif request._in_do:
        request.connection.engine.callback(_receive_timeout, request)
        return

    # Make sure we've got the right thing.
    if not request._waiting or not isinstance(request._waiting[-1], _Receiver):
        return

    # Remove this from the receivers.
    recv = request._waiting.pop()

    if recv[0] in receivers and recv.ref in receivers[recv[0]]:
        receivers[recv[0]].remove(recv.ref)

    _do(request, TimeoutError(), True)


###############################################################################
# Asynchronous Internals
###############################################################################

def _init(request):
    # Set a bit of state for the request.
    request._chunked = False
    request._charset = "utf-8"
    request._tb = None
    request._callbacks = {}
    request._waiting = []
    request._unhandled = []

    # Create a RequestContext.
    request._context = RequestContext()

    # Set a flag on the request so Application won't finish processing it.
    request.auto_finish = False


def _cleanup(request):
    """
    Delete the context manager and everything else.
    """
    # The Basics
    del request._context
    del request._gen
    del request._tb

    # Stream Variables
    del request._chunked
    del request._charset
    del request._writer

    # Asynchronous Internals
    request._callbacks.clear()
    del request._callbacks
    del request._waiting
    del request._unhandled


def _do(request, input, as_exception=False):
    """
    Send the provided input to the request handler and get and process the
    output.
    """
    errored = False

    try:
        request._in_do = True

        while True:
            with request._context as app:
                # Make sure we're connected.
                if not request.connection.connected:
                    try:
                        # Bubble up an error so the user's code can do something
                        # about this.
                        request._gen.throw(RequestClosed())
                    except RequestClosed:
                        # Don't react at all.
                        pass
                    finally:
                        _cleanup(request)
                        return

                try:
                    if as_exception:
                        output = request._gen.throw(input)
                    else:
                        output = request._gen.send(input)

                except StopIteration:
                    # We've run out of content.
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
                    request._rule_content_type = None
                    request._rule_headers = None
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
                    request._rule_content_type = None
                    request._rule_headers = None
                    output = err

                except Exception as err:
                    if request._started:
                        log.exception("Error while handling asynchronous "
                                      "request: %s %s" % (request.method,
                                                          request.uri))
                        request.connection.close(False)
                        _cleanup(request)
                        return

                    errored = True
                    request._rule_content_type = None
                    request._rule_headers = None
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
                _finish(request, output, True)
                return

            # Now that we're out of the request context, let's see what we've got to
            # work with.
            if isinstance(output, Sleeper):
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
                if request._writer(request, output, errored) is Again:
                    input = None
                    as_exception = False
                    continue

            # We *have* to continue if we don't want to break.
            break

    finally:
        request._in_do = False
