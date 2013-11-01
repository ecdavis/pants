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
``pants.web.application`` implements a minimalistic framework for building
websites on top of Pants.

The :class:`~pants.web.application.Application` class features a powerful,
easy to use request routing system and an API similar to that of the popular
`Flask <http://flask.pocoo.org/>`_ project.

.. note::

    Application does not provide out of the box support for sessions or
    templates, and it is not compatible with WSGI middleware as it is not
    implemented via WSGI.


Applications
============

Instances of the :class:`Application` class are callable and act as request
handlers for the :class:`pants.http.server.HTTPServer` class. As such, to
implement a server you just have to create an
:class:`~pants.http.server.HTTPServer` instance using your application.

.. code-block:: python

    from pants.http import HTTPServer
    from pants.web import Application

    app = Application()

    HTTPServer(app).listen(8080)

Alternatively, you may call the Application's :func:`~Application.run` method,
which creates an instance of HTTPServer for you and starts Pants' global
:mod:`~pants.engine`.

The main features of an Application are its powerful request routing table and
its output handling.

.. _app-routing:

Routing
=======

When registering new request handlers with an :class:`Application` instance,
you are required to provide a specially formatted rule. These rules allow you
to capture variables from URLs on top of merely routing requests, making it
easy to create attractive URLs bereft of unfriendly query strings.

Rules in their simplest form will match a static string.

.. code-block:: python

    @app.route("/")
    def index(request):
        return "Index Page"

    @app.route("/welcome")
    def welcome(request):
        return "Hello, Programmer!"

Such an Application would have two pages, and not be exceptionally useful by
any definition. Adding a simple variable makes things much more interesting.

.. code-block:: python

    @app.route("/welcome/<name>")
    def welcome(request, name):
        return "Hello, %s!" % name

Variables are created using inequality signs, as demonstrated above, and allow
you to capture data directly from a URL. By default, a variable accepts any
character except a slash (``/``) and returns the entire captured string as an
argument to your request handler.

It is possible to change this behavior by naming a :class:`Converter` within
the variable definition using the format ``<converter:name>`` where
``converter`` is the name of the converter to use. It is not case-sensitive.
For example, the ``int`` converter:

.. code-block:: python

    @app.route("/user/<int:id>")
    def user(request, id):
        return session.query(User).filter_by(id=id).first().username

In the above example, the ``id`` is automatically converted to an integer by
the framework. The converter also serves to limit the URLs that will match a
rule. Variables using the ``int`` converter will only match numbers.

Finally, you may provide default values for variables:

.. code-block:: python

    @app.route("/page/<path:slug=welcome>")

Default values are used if there is no string to capture for the variable in
question, and are processed via the converter's :meth:`~Converter.decode`
method each time the rule is matched.

When using default values, they allow you to omit the entirety of the URL
following the point at which they are used. As such, if you have a rule such
as ``/page/<int:id=2>/other``, the URL ``/page/`` will match it.


Domains
-------

The route rule strings are very similar to those used by the popular Flask
framework. However, in addition to that behavior, the Application allows you
to match and extract variables from the domain the page was requested from.

.. code-block:: python

    @app.route("<username>.my-site.com/blog/<int:year>/<slug>")

To use domains, simply place the domain before the first slash in the
route rule.


Rule Variable Converters
========================

Converters are all subclasses of :class:`Converter` that have been registered
with Pants using the :func:`register_converter` decorator.

A Converter has three uses:

1. Generating a regular expression snippet that will match only valid input for
   the variable in question.
2. Processing the captured string into useful data for the Application.
3. Encoding values into URL-friendly strings for inclusion into URLs generated
   via the :func:`url_for` method.

Converters can accept configuration information from rules using a basic
format.

.. code-block:: python

    @app.route("/page/<regex('(\d{3}-\d{4})'):number>")

    @app.route("/user/<id(digits=4 min=200):id>")

Configuration must be provided within parenthesis, with separate values
separated by simple spaces. Strings may be enclosed within quotation marks if
they need to contain spaces.

The values ``true``, ``false``, and ``none`` are converted to the appropriate
Python values before being passed to the Converter's configuration method and it
also attempts to convert values into integers or floats if possible. Use
quotation marks to avoid this behavior if required.

Arguments may be passed by order or by key, and are passed to the Converter's
:func:`~Converter.configure` method from the constructor
via: ``self.configure(*args, **kwargs)``

Several basic converters have been included by default to make things easier.

Any
---

The ``any`` converter will allow you to match one string from a list of possible
strings.

.. code-block:: python

    @app.route("/<any(call text im):action>/<int:id>")

Using the above rule, you can match URLs starting with ``/call/``, ``/text/``,
or ``/im/`` (and followed, of course, by an integer named id).


DomainPart
----------

DomainPart is a special converter used when matching sections of a domain name
that will not match a period (``.``) but that otherwise works identically to the
default String converter.

You do not have to specify the DomainPart converter. It will be used
automatically in place of String for any variable capture within the domain name
portion of the rule.


Float
-----

The ``float`` converter will match a negation, the digits 0 through 9, and a
single period. It automatically converts the captured string into a
floating point number.

=========  ========  ============
Argument   Default   Description
=========  ========  ============
min        None      The minimum value to allow.
max        None      The maximum value to allow.
=========  ========  ============

Values outside of the range defined by ``min`` and ``max`` will result in an
error and *not* merely the rule not matching the URL.


Integer
-------

The ``int`` (or ``integer``) converter will match a negation and the digits
0 through 9, automatically converting the captured string into an integer.

=========  ========  ============
Argument   Default   Description
=========  ========  ============
digits     None      The exact number of digits to match with this variable.
min        None      The minimum value to allow.
max        None      The maximum value to allow.
=========  ========  ============

As with the Float converter, values outside of the range defined by ``min`` and
``max`` will result in an error and *not* merely the rule not matching the URL.


Path
----

The ``path`` converter will match any character at all and merely returns the
captured string. This is useful as a catch all for placing on the end of URLs.


Regex
-----

The ``regex`` converter allows you to specify an arbitrary regular expression
snippet for inclusion into the rule's final expression.

=========  ========  ============
Argument   Default   Description
=========  ========  ============
match                A regular expression snippet for inclusion into the rule's final expression.
namegen    None      The string format to use when building a URL for this variable with :func:`~pants.web.application.url_for`.
=========  ========  ============

.. code-block:: python

    @app.route("/call/<regex('(\d{3}-\d{4})'):number>")

The above variable would match strings such as ``555-1234``.


String
------

The ``string`` converter is the default converter used when none is specified,
and it matches any character except for a slash (``/``), allowing it to easily
capture individual URL segments.

=========  ========  ============
Argument   Default   Description
=========  ========  ============
min        None      The minimum length of the string to capture.
max        None      The maximum length of the string to capture.
length     None      An easy way to set both ``min`` and ``max`` at once.
=========  ========  ============

.. note::

    Setting ``length`` overrides any value of ``min`` and ``max``.


Writing a Variable Converter
============================

To create your own variable converters, you must create subclasses of
:class:`Converter` and register it with Pants using the
decorator :func:`register_converter`.

The simplest way to use converters is as a way to store common regular
expressions that you use to match segments of a URL. If, for example, you need
to match basic phone numbers, you could use:

.. code-block:: python

    @app.route("/tel/<regex('(\d{3})-(\d{4})'):number>")

Placing the expression in the route isn't clean, however, and it can be a pain
to update--particularly if you use the same expression across many different
routes.

A better alternative is to use a custom converter:

.. code-block:: python

    from pants.web import Converter, register_converter

    @register_converter
    class Telephone(Converter):
        regex = r"(\d{3})-(\d{4})"

After doing that, your rule becomes as easy as ``/tel/<telephone:number>``. Of
course, you could stop there, and deal with the resulting tuple of two strings
within your request handler.

However, the main goal of converters is to *convert* your data. Let's store our
phone number in a :class:`collections.namedtuple`. While we're at it, we'll
switch to a slightly more complex regular expression that can capture area codes
and extensions as well.

.. code-block:: python

    from collections import namedtuple
    from pants.web import Converter, register_converter

    PhoneNumber = namedtuple('PhoneNumber', ['npa','nxx','subscriber', 'ext'])

    @register_converter
    class Telephone(Converter):
        regex = r"(?:1[ -]*)?(?:\(? *([2-9][0-9]{2}) *\)?[ -]*)?([2-9](?:1[02-9]|[02-9][0-9]))[ -]*(\d{4})(?:[ -]*e?xt?[ -]*(\d+))?"

        def decode(self, request, *values):
            return PhoneNumber(*(int(x) if x else None for x in values))

Now we're getting somewhere. Using our existing rule, now we can make a request
for the URL ``/tel/555-234-5678x115`` and our request handler will receive the
variable ``PhoneNumber(npa=555, nxx=234, subscriber=5678, ext=115)``.

Lastly, we need a way to convert our nice ``PhoneNumber`` instances into
something we can place in a URL, for use with the :func:`url_for` function:

.. code-block:: python

    @register_converter
    class Telephone(Converter):

        ...

        def encode(self, request, value):
            out = '%03d-%03d-%04d' % (value.npa, value.nxx, value.subscriber)
            if value.ext:
                out += '-ext%d' % value.ext
            return out

Now, we can use ``url_for('route', PhoneNumber(npa=555, nxx=234, subscriber=5678, ext=115))``
and get a nice and readable ``/tel/555-234-5678-ext115`` back (assuming the rule
for ``route`` is ``/tel/<telephone:number>``).


Output Handling
===============

Sending output from a request handler is as easy as returning a value from the
function. Strings work well:

.. code-block:: python

    @app.route("/")
    def index(request):
        return "Hello, World!"

The example above would result in a ``200 OK`` response with the headers
``Content-Type: text/plain`` and ``Content-Length: 13``.


Response Body
-------------

If the returned string begins with ``<!DOCTYPE`` or ``<html`` it will be
assumed that the ``Content-Type`` should be ``text/html`` if a content type is
not provided.

If a unicode string is returned, rather than a byte string, it will be encoded
automatically using the encoding specified in the ``Content-Type`` header. If
that header is missing, or does not contain an encoding, the document will be
encoded in ``UTF-8`` by default and the content type header will be updated.

Dictionaries, lists, and tuples will be automatically converted into
`JSON <http://en.wikipedia.org/wiki/JSON>`_ and the ``Content-Type`` header
will be set to ``application/json``, making it easy to send JSON to clients.

If any other object is returned, the Application will attempt to cast it into
a byte string using ``str(object)``. To provide custom behavior, an object may
be given a ``to_html`` method, which will be called rather than ``str()``. If
``to_html`` is used, the ``Content-Type`` will be assumed to be ``text/html``.


Status and Headers
------------------

Of course, in any web application it is useful to be able to return custom
status codes and HTTP headers. To do so from an Application's request handlers,
simply return a tuple of ``(body, status)`` or ``(body, status, headers)``.

If provided, ``status`` must be an integer or a byte string. All valid HTTP
response codes may be sent simply by using their numbers.

If provided, ``headers`` must be either a dictionary, or a list of tuples
containing key/value pairs (``[(heading, value), ...]``).

You may also use an instance of :class:`pants.web.application.Response` rather
than a simple body or tuple.

The following example returns a page with the status code ``404 Not Found``:

.. code-block:: python

    @app.route("/nowhere/")
    def nowhere(request):
        return "This does not exist.", 404


"""

###############################################################################
# Imports
###############################################################################

import re
import traceback
import urllib

from datetime import datetime

from pants.http.server import HTTPServer
from pants.http.utils import HTTP, HTTPHeaders

from pants.web.utils import decode, ERROR_PAGE, HAIKUS, HTTP_MESSAGES, \
    HTTPException, HTTPTransparentRedirect, log, NO_BODY_CODES, CONSOLE_JS

try:
    import simplejson as json
except ImportError:
    import json


###############################################################################
# Constants
###############################################################################

__all__ = (
    "Converter", "register_converter",  # Converter Functions
    "Response", "Module", "Application", "HTTPServer",  # Core Classes

    "abort", "all_or_404", "error", "redirect", "url_for"  # Helper Functions
)

RULE_PARSER = re.compile(r"<(?:([a-zA-Z_][a-zA-Z0-9_]+)(?:\(((?:\"[^\"]+\"|[^:>)]*)+)\))?:)?([a-zA-Z_][a-zA-Z0-9_]+)(?:=([^>]*))?>([^<]*)")
OPTIONS_PARSER = re.compile(r"""(?:(\w+)=)?(None|True|False|\d+\.\d+|\d+\.|\d+|"[^"]*?"|'[^']*?'|\w+)""", re.IGNORECASE)

# Unique object for URL building.
NoValue = object()


###############################################################################
# JSONEncoder Class
###############################################################################

class JSONEncoder(json.JSONEncoder):
    """
    This subclass of JSONEncoder adds support for serializing datetime objects.
    """
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)


###############################################################################
# Context Manager
###############################################################################

class RequestContext(object):
    __slots__ = ('application', 'request', 'stack')

    def __init__(self, application=None, request=None):
        self.application = application or Application.current_app
        self.request = request or self.application.request
        self.stack = []

    def __enter__(self):
        self.stack.append((Application.current_app, self.application.request))

        Application.current_app = ca = self.application
        ca.request = self.request

        return ca

    def __exit__(self, exc_type, exc_val, exc_tb):
        Application.current_app, self.application.request = self.stack.pop()


###############################################################################
# Converter Class
###############################################################################

class Converter(object):
    """
    The Converter class is the base class for all the different value
    converters usable in routing rules.
    """

    regex = "([^/]+)"

    def __init__(self, options, default):
        # Handle the options.
        self.default = default
        args, kwargs = [], {}
        if options:
            for key, val in OPTIONS_PARSER.findall(options):
                if val.lower() == 'none':
                    val = None
                elif val.lower() == 'true':
                    val = True
                elif val.lower() == 'false':
                    val = False
                else:
                    try:
                        val = int(val)
                    except ValueError:
                        try:
                            val = float(val)
                        except ValueError:
                            pass

                if isinstance(val, basestring):
                    val = val
                    if (val[0] == '"' and val[-1] == '"') or \
                            (val[0] == "'" and val[-1] == "'"):
                        val = val[1:-1]

                if key:
                    kwargs[key] = val
                else:
                    args.append(val)

        # Now, configure it with those settings.
        #noinspection PyArgumentList
        self.configure(*args, **kwargs)

        # Count our capture groups.
        self._regex = re.compile("^%s$" % self.regex)
        self.capture_groups = self._regex.groups

    def __repr__(self):
        out = ""
        if self.default:
            out += " default=" + repr(self.default)
        if hasattr(self, 'regex'):
            out += ' regex=' + repr(self.regex)
        return "<Converter[%s]%s>" % (self.__class__.__name__, out)

    def __call__(self, request, *values):
        if not any(values):
            m = self._regex.match(self.default)
            if not m:
                raise HttpException('Invalid default value for converter: %s', self.default)
            values = m.groups()
        return self.decode(request, *values)

    def configure(self):
        """
        The method receives configuration data parsed from the rule creating
        this Converter instance as positional and keyword arguments.

        You must build a regular expression for matching acceptable input within
        this function, and save it as the instance's ``regex`` attribute. You
        may use more than one capture group.
        """
        pass

    def decode(self, request, *values):
        """
        This method receives captured strings from URLs and must process the
        strings and return variables usable within request handlers.

        If the converter's regular expression has multiple capture groups, it
        will receive multiple arguments.

        .. note::

            Use :func:`abort` or raise an :class:`HTTPException` from this
            method if you wish to display an error page. Any other uncaught
            exceptions will result in a ``400 Bad Request`` page.

        """
        return values[0] if len(values) == 1 else values

    def encode(self, request, value):
        """
        This method encodes a value into a URL-friendly string for inclusion
        into URLs generated with :func:`url_for`.
        """
        return str(value)


###############################################################################
# Built-In Converters
###############################################################################

CONVERTER_TYPES = {}

def register_converter(name=None, klass=None):
    """
    Register a converter with the given name. If a name is not provided, the
    class name will be converted to lowercase and used instead.
    """
    try:
        if issubclass(name, Converter):
            name, klass = None, name
    except TypeError:
        pass

    def decorator(klass):
        _name = name if name else klass.__name__.lower()
        CONVERTER_TYPES[_name] = klass
        return klass

    if klass:
        return decorator(klass)
    return decorator


@register_converter
class Regex(Converter):
    def configure(self, match, namegen=None):
        self.regex = match
        if namegen is not None:
            self.namegen = namegen

    def encode(self, request, value):
        if hasattr(self, 'namegen'):
            return namegen.format(value)
        return str(value)


@register_converter
class Any(Converter):
    def configure(self, *choices):
        self.regex = "(%s)" % '|'.join(re.escape(x) for x in choices)

        if self.default is not None:
            dl = self.default.lower()
            for choice in choices:
                if choice.lower() == dl:
                    self.default = choice
                    break
            else:
                raise ValueError("Default value %r is not a valid "
                                 "choice." % self.default)


@register_converter
class DomainPart(Converter):
    def configure(self, min=None, max=None, length=None):
        if length is not None:
            min, max = length, length

        if min is None and max is None:
            self.regex = "([^/.]+)"
        elif min == max:
            self.regex = "([^/.]{%d})" % min
        elif max is None:
            self.regex = "([^/.]{%d,})" % min
        else:
            self.regex = "([^/.]{%d,%d})" % (min, max)


@register_converter
class Float(Converter):
    def configure(self, min=None, max=None):
        # Depending on the value of min, allow it to match a negation.
        if min is None or min < 0:
            self.regex = "(-?\d+(?:\.\d+)?)"
        else:
            self.regex = "(\d+(?:\.\d+)?)"

        self.min = min
        self.max = max

    def decode(self, request, value):
        value = float(value)
        if (self.min is not None and value < self.min) or\
           (self.max is not None and value > self.max):
            raise ValueError("Value %d is out of range." % value)
        return value


@register_converter('int')
@register_converter
class Integer(Converter):
    def configure(self, digits=None, min=None, max=None):
        # Build the correct regex for the length.
        minus = "-?" if min is None or min < 0 else ""
        if digits:
            self.regex = "(%s\d{%d})" % (minus, digits)
        else:
            self.regex = "(%s\d+)" % minus

        self.min = min
        self.max = max
        self.digits = digits

    def decode(self, request, value):
        value = int(value)
        if (self.min is not None and value < self.min) or\
           (self.max is not None and value > self.max):
            raise ValueError("Value %d is out of range." % value)
        return value

    def encode(self, request, value):
        if self.digits:
            minus = '-' if value < 0 else ''
            return ('%s%%0%dd' % (minus, self.digits)) % abs(value)

        else:
            return str(value)


@register_converter
class Path(Converter):
    regex = "(.+?)"


@register_converter
class String(Converter):
    def configure(self, min=None, max=None, length=None):
        if length is not None:
            min, max = length, length

        if min is None and max is None:
            self.regex = "([^/]+)"
        elif min == max:
            self.regex = "([^/]{%d})" % min
        elif max is None:
            self.regex = "([^/]{%d,})" % min
        else:
            self.regex = "([^/]{%d,%d})" % (min, max)


###############################################################################
# Response Class
###############################################################################

class Response(object):
    """
    The Response object is entirely optional, and provides a convenient way to
    glue the body, status code, and HTTP headers into one object to return from
    your routes.

    =========  ==================  ============
    Argument   Default             Description
    =========  ==================  ============
    body       ``None``            *Optional.* The response body to send back to the client.
    status     ``200``             *Optional.* The HTTP status code of the response.
    headers    ``HTTPHeaders()``   *Optional.* HTTP headers to send with the response.
    =========  ==================  ============
    """

    def __init__(self, body=None, status=None, headers=None):
        self.body = body or ""
        self.status = status or 200
        self.headers = headers or HTTPHeaders()

    def __repr__(self):
        return '<Response[%r] at 0x%08X>' % (self.status, id(self))


###############################################################################
# Module Class
###############################################################################

class Module(object):
    """
    A Module is, essentially, a group of rules for an Application. Rules grouped
    into a Module can be created without any access to the final Application
    instance, making it simple to split a website into multiple Python modules
    to be imported in the module that creates and runs the application.
    """

    def __init__(self, name=None):
        # Internal Stuff
        self._modules = {}
        self._routes = {}
        self._parents = set()

        # External Stuff
        self.name = name

        self.hooks = {
            'request_started': [],
            'request_finished': [],
            'request_teardown': []
            }

    def __repr__(self):
        return "<Module(%r) at 0x%08X>" % (self.name, id(self))

    ##### Module Connection ###################################################

    def add(self, rule, module):
        """
        Add a Module to this Module under the given rule. All rules within the
        sub-module will be accessible to this Module, with their rules prefixed
        by the rule provided here.

        For example::

            module_one = Module()

            @module_one.route("/fish")
            def fish(request):
                return "This is fish."

            module_two = Module()

            module_two.add("/pie", module_one)

        Given that code, the request handler ``fish`` would be available from
        the Module ``module_two`` with the rules ``/pie/fish``.
        """
        if isinstance(module, Application):
            raise TypeError("Applications cannot be added as modules.")

        # Register this module with the child module.
        module._parents.add(self)

        if not '/' in rule:
            rule = '/' + rule
        self._modules[rule] = module

        # Now, recalculate.
        self._recalculate_routes()

    def _recalculate_routes(self, processed=tuple()):
        if self in processed:
            raise RuntimeError("Cyclic inheritance: %s" %
                               ", ".join(repr(x) for x in processed))

        for parent in self._parents:
            parent._recalculate_routes(processed=processed + (self,))


    ##### Hook Decorators #####################################################

    def request_started(self, func):
        """
        Register a method to be executed immediately after a request has been
        successfully routed and before the request handler is executed.

        .. note::

            Hooks, including ``request_started``, are not executed if there is
            no matching rule to handle the request.

        This can be used for the initialization of sessions, a database
        connection, or other details. However, it is not always the best choice.
        If you wish to modify *all* requests, or manipulate the URL before
        routing occurs, you should wrap the Application in another method,
        rather than using a ``request_started`` hook. As an example of the
        difference:

        .. code-block:: python

            from pants.web import Application
            from pants.http import HTTPServer
            from pants import Engine

            from my_site import sessions, module

            app = Application()

            # The Hook
            @app.request_started
            def handle(request):
                logging.info('Request matched route: %s' % request.route_name)

            # The Wrapper
            def wrapper(request):
                request.session = sessions.get(request.get_secure_cookie('session_id'))
                app(request)

            # Add rules from another module.
            app.add('/', module)

            HTTPServer(wrapper).listen()
            Engine.instance().start()

        """
        self.hooks['request_started'].append(func)
        self._recalculate_routes()
        return func

    def request_finished(self, func):
        """
        Register a method to be executed immediately after the request handler
        and before the output is processed and send to the client.

        This can be used to transform the output of request handlers.

        .. note::

            These hooks are not run if there is no matching rule for a request,
            if there is an exception while running the request handler, or if
            the request is not set to have its output processed by the
            Application by setting ``request.auto_finish`` to ``False``.
        """
        self.hooks['request_finished'].append(func)
        self._recalculate_routes()
        return func

    def request_teardown(self, func):
        """
        Register a method to be executed after the output of a request handler
        has been processed and has begun being transmitted to the client. At
        this point, the request is not going to be used again and can be cleaned
        up.

        .. note::

            These hooks will always run if there was a matching rule, even if
            the request handler or other hooks have exceptions, to prevent any
            potential memory leaks from requests that aren't torn down properly.
        """
        self.hooks['request_teardown'].append(func)
        self._recalculate_routes()
        return func


    ##### Route Management Decorators #########################################

    def basic_route(self, rule, name=None, methods=('GET', 'HEAD'),
                    headers=None, content_type=None, func=None):
        """
        The basic_route decorator registers a route with the Module without
        holding your hand about it.

        It functions similarly to the :func:`Module.route` decorator, but it
        doesn't wrap the function with any argument processing code. Instead,
        the function is given only the request object, and through it access to
        the regular expression match.

        Example Usage::

            @app.basic_route("/char/<char>")
            def my_route(request):
                char, = request.match.groups()
                return "The character is %s!" % char

        That is essentially equivalent to::

            @app.route("/char/<char>")
            def my_route(request, char):
                return "The character is %s!" % char

        .. note::

            Output is still handled the way it is with a normal route, so you
            can return strings and dictionaries as usual.

        =============  ============
        Argument       Description
        =============  ============
        rule           The route rule to match for a request to go to the decorated function. See :func:`Module.route` for more information.
        name           *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods        *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        headers        *Optional.* A dictionary of HTTP headers to always send with the response from this request handler. Any headers set within the request handler will override these headers.
        content_type   *Optional.* The HTTP Content-Type header to send with the response from this request handler. A Content-Type header set within the request handler will override this.
        func           *Optional.* The function for this view. Specifying the function bypasses the usual decorator-like behavior of this function.
        =============  ============
        """
        if not '/' in rule:
            rule = '/' + rule

        def decorator(func):
            if not callable(func):
                raise ValueError("Request handler must be callable.")

            if name is None:
                if hasattr(func, "__name__"):
                    _name = func.__name__
                elif hasattr(func, "__class__"):
                    _name = func.__class__.__name__
                else:
                    raise ValueError("Cannot find name for rule. Please "
                                     "specify name manually.")
            else:
                _name = name

            # Get the rule table for this rule.
            rule_table = self._routes.setdefault(rule, {})
            if isinstance(rule_table, Module):
                raise ValueError("The rule %r is claimed by a Module." % rule)

            # Now, for each method, store the data.
            for method in methods:
                rule_table[method] = (func, _name, False, False, headers,
                                      content_type)

            # Recalculate routes and return.
            self._recalculate_routes()
            return func

        if func:
            return decorator(func)
        return decorator

    def route(self, rule, name=None, methods=('GET','HEAD'), auto404=False,
              headers=None, content_type=None, func=None):
        """
        The route decorator is used to register a new route with the Module
        instance. Example::

            @app.route("/")
            def hello_world(request):
                return "Hiya, Everyone!"

        .. seealso::

            See :ref:`app-routing` for more information on writing rules.

        =============  ============
        Argument       Description
        =============  ============
        rule           The route rule to be matched for the decorated function to be used for handling a request.
        name           *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods        *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        auto404        *Optional.* If this is set to True, all response handler arguments will be checked for truthiness (True, non-empty strings, etc.) and, if any fail, a ``404 Not Found`` page will be rendered automatically.
        headers        *Optional.* A dictionary of HTTP headers to always send with the response from this request handler. Any headers set within the request handler will override these headers.
        content_type   *Optional.* The HTTP Content-Type header to send with the response from this request handler. A Content-Type header set within the request handler will override this.
        func           *Optional.* The function for this view. Specifying the function bypasses the usual decorator-like behavior of this function.
        =============  ============
        """
        if not '/' in rule:
            rule = '/' + rule

        def decorator(func):
            if not callable(func):
                raise ValueError("Request handler must be callable.")

            if name is None:
                if hasattr(func, "__name__"):
                    _name = func.__name__
                elif hasattr(func, "__class__"):
                    _name = func.__class__.__name__
                else:
                    raise ValueError("Cannot find name for rule. Please "
                                     "specify name manually.")
            else:
                _name = name

            # Get the rule table for this rule.
            rule_table = self._routes.setdefault(rule, {})
            if isinstance(rule_table, Module):
                raise ValueError("The rule %r is claimed by a Module." % rule)

            # Now, for each method, store the data.
            for method in methods:
                rule_table[method] = (func, _name, True, auto404, headers, content_type)

            # Recalculate and return.
            self._recalculate_routes()
            return func

        if func:
            return decorator(func)
        return decorator


###############################################################################
# Application Class
###############################################################################

class Application(Module):
    """
    The Application class builds upon the :class:`Module` class and acts as a
    request handler for the :class:`~pants.http.server.HTTPServer`, with request
    routing, error handling, and a degree of convenience that makes sending
    output easier.

    Instances of Application are callable, and should be used as a HTTPServer's
    request handler.

    =========  ================================================================
    Argument   Description
    =========  ================================================================
    debug      *Optional.* If this is set to True, the automatically generated
               ``500 Internal Server Error`` pages will display additional
               debugging information.
    =========  ================================================================
    """
    current_app = None
    request = None

    def __init__(self, name=None, debug=False, fix_end_slash=False):
        super(Application, self).__init__(name)

        # Internal Stuff
        self._route_table = {}
        self._route_list = []
        self._name_table = {}

        # External Stuff
        self.json_encoder = JSONEncoder
        self.debug = debug
        self.fix_end_slash = fix_end_slash

    def run(self, address=None, ssl_options=None, engine=None):
        """
        This function exists for convenience, and when called creates a
        :class:`~pants.http.server.HTTPServer` instance with its request
        handler set to this application instance, calls
        :func:`~pants.http.server.HTTPServer.listen` on that HTTPServer, and
        finally, starts the Pants engine to process requests.

        ============  ============
        Argument      Description
        ============  ============
        address       *Optional.* The address to listen on. If this isn't specified, it will default to ``('', 80)``.
        ssl_options   *Optional.* A dictionary of SSL options for the server. See :meth:`pants.server.Server.startSSL` for more information.
        engine        *Optional.* The :class:`pants.engine.Engine` instance to use.
        ============  ============
        """
        if not engine:
            from pants.engine import Engine
            engine = Engine.instance()

        HTTPServer(self, ssl_options=ssl_options, engine=engine).listen(address)
        engine.start()

    ##### Error Handlers ######################################################

    def handle_404(self, request, err):
        if isinstance(err, HTTPException):
            return error(err.message, 404, request=request)
        return error(404, request=request)

    def handle_500(self, request, err):
        log.exception("Error handling HTTP request: %s %s" %
                      (request.method, request.url))
        if not self.debug:
            return error(500, request=request)

        # See if we can highlight the traceback.
        tb = getattr(request, '_tb', None) or traceback.format_exc()

        # Try to highlight the traceback.
        if hasattr(self, 'highlight_traceback'):
            try:
                tb = self.highlight_traceback(request, err, tb)
                if not u"<pre>" in tb:
                    tb = u"<pre>%s</pre>" % tb
            except Exception as err:
                log.exception("Error in highlight_traceback for %r." % self)
                tb = u"<pre>%s</pre>" % tb
        else:
            tb = u"<pre>%s</pre>" % tb

        response = u"\n".join([
            u"<h2>Traceback</h2>", tb,
            #u'<div id="console"><script type="text/javascript">%s</script></div>' % CONSOLE_JS,
            u"<h2>Route</h2>",
            u"<pre>route name   = %r" % getattr(request, "route_name", None),
            u"match groups = %r" % (request.match.groups() if request.match else None,),
            (u"match values = %r</pre>" % request._converted_match) if hasattr(request, '_converted_match') else u"</pre>",
            u"<h2>HTTP Request</h2>",
            request.__html__()
        ])

        return error(response, 500, request=request)

    ##### Routing Table Builder ###############################################

    def _recalculate_routes(self, processed=None, path=None, module=None,
                            nameprefix="", hooks=None):
        """
        This function does the heavy lifting of building the routing table, and
        it's called every time a route is updated. Fortunately, that generally
        only happens when the application is being created.
        """
        if path is None:
            # Initialize our storage variables.
            self._route_list = []
            self._route_table = {}
            self._name_table = {}

        # Get the unprocessed route table.
        routes = module._routes if module else self._routes
        modules = module._modules if module else self._modules
        mod_hooks = module.hooks if module else self.hooks

        # Update the name prefix.
        name = module.name if module else self.name
        if name:
            nameprefix = nameprefix + "." + name if nameprefix else name

        # Update the hooks system.
        if hooks:
            new_hooks = {}
            for k, v in hooks.iteritems():
                new_hooks[k] = v[:]
            hooks = new_hooks
        else:
            hooks = {}

        for k,v in mod_hooks.iteritems():
            if k in hooks:
                hooks[k].extend(v)
            else:
                hooks[k] = v[:]

        # Iterate through modules first, so our own rules are more important.
        for rule, mod in modules.iteritems():
            self._recalculate_routes(None, rule, mod, nameprefix, hooks)

        # Iterate through the unprocessed route table.
        for rule, table in routes.iteritems():
            # If path is set, and this isn't an absolute rule, merge the rule
            # with the path.
            if path and (rule[0] == "/" or not "/" in rule):
                if path[-1] == "/":
                    if rule[0] == "/":
                        rule = path + rule[1:]
                    else:
                        rule = path + rule
                else:
                    if rule[0] == "/":
                        rule = path + rule
                    else:
                        rule = path + "/" + rule

            # Parse the rule string.
            regex, converters, names, namegen, domain, rpath = \
                _rule_to_regex(rule)
            dkey, rkey = rule.split("/", 1)

            # Get the domain table.
            if not dkey in self._route_table:
                dt = self._route_table[dkey] = {}
                dl = dt[None] = [domain, dkey, []]
                self._route_list.append(dl)
            else:
                dt = self._route_table[dkey]
                dl = dt[None]

            # Determine if this is a new rule for the given domain.
            if not rkey in dt:
                rt = dt[rkey] = {}
                rl = rt[None] = [rpath, re.compile(regex), rkey, None, {},
                                 names, namegen, converters]
                dl[2].append(rl)
            else:
                rt = dt[rkey]
                rl = rt[None]

            # Get the method table
            method_table = rl[4]

            # Iterate through all the methods this rule provides.
            for method, (func, name, advanced, auto404, headers, content_type) \
                    in table.iteritems():
                method = method.upper()
                if method == 'GET' or rl[3] is None:
                    if nameprefix:
                        name = nameprefix + '.' + name
                    rl[3] = name
                if advanced:
                    for mthd in method_table:
                        if getattr(method_table[mthd], "wrapped_func", None) \
                                is func:
                            method_table[method] = method_table[mthd], \
                                                   headers, content_type
                            break
                    else:
                        method_table[method] = _get_runner(func, converters,
                                                            auto404), headers, \
                                                            content_type, hooks
                else:
                    method_table[method] = func, headers, content_type, hooks

            # Update the name table.
            self._name_table[rl[3]] = rl

        if path is None:
            # Sort everything.

            # Sort the domains first by the length of the domain key, in reverse
            # order; followed by the number of colons in the domain key, in
            # reverse order; and finally by the domain key alphabetically.
            self._route_list.sort(key=lambda x: (-len(x[1]), -(x[1].count(':')),
                                                 x[1]))

            # Sort the same way for each rule in each domain, but using the rule
            # key rather than the domain key.
            for domain, dkey, rl in self._route_list:
                rl.sort(key=lambda x: (-len(x[2]), -(x[2].count(':')), x[2]))

    ##### The Request Handler #################################################

    def __call__(self, request):
        """
        This function is called when a new request is received, and uses the
        method :meth:`Application.route_request` to select and execute the
        proper request handler, and then the method
        :meth:`Application.parse_output` to process the handler's output.
        """
        Application.current_app = self
        self.request = request

        try:
            request.auto_finish = True
            result = self.route_request(request)
            if request.auto_finish:
                self.parse_output(result)

        except Exception as err:
            # This should hopefully never happen, but it *could*.
            try:
                body, status, headers = self.handle_500(request, err)
            except Exception:
                # There's an error with our handle_500.
                log.exception("There was a problem handling a request, "
                              "and a problem running Application.handle_500 "
                              "for %r." % self)
                body, status, headers = error(500, request=request)

                # If an exception happens at *this* point, it's destined. Just
                # show the ugly page.

            if not 'Content-Length' in headers:
                headers['Content-Length'] = len(body)

            request.send_status(status)
            request.send_headers(headers)
            request.write(body)
            request.finish()

        finally:
            if hasattr(request, '_hooks'):
                hks = request._hooks.get('request_teardown')
                if hks:
                    for hf in hks:
                        try:
                            hf(request)
                        except Exception as err:
                            # Log the exception, but continue.
                            log.exception("There was a problem handling a "
                                          "request teardown hook for: %r",
                                            request)

            if hasattr(request, '_converted_match'):
                del request._converted_match

            Application.current_app = None
            self.request = None

    def route_request(self, request):
        """
        Determine which request handler to use for the given request, execute
        that handler, and return its output.
        """
        domain = request.hostname
        path = urllib.unquote_plus(request.path)
        matcher = domain + path
        method = request.method.upper()
        available_methods = set()

        request._rule_headers = None
        request._rule_content_type = None

        for dmn, dkey, rules in self._route_list:
            # Do basic domain matching.
            if ':' in dmn:
                if not request.host.lower().endswith(dmn):
                    continue
            elif not domain.endswith(dmn):
                continue

            # Iterate through the available rules, trying for a match.
            for rule, regex, rkey, name, method_table, names, namegen, \
                    converters in rules:
                if not path.startswith(rule):
                    continue
                match = regex.match(matcher)
                if match is None:
                    continue

                # We have a match. Check for a valid method.
                if not method in method_table:
                    available_methods.update(method_table.keys())
                    continue

                # It's a match. Run the method and return the result.
                request.route_name = name
                request.match = match

                try:
                    func, headers, content_type, hooks = method_table[method]
                    request._rule_headers = headers
                    request._rule_content_type = content_type
                    request._hooks = hooks

                    hks = hooks.get('request_started')
                    if hks:
                        for hf in hks:
                            hf(request)

                    output = func(request)

                    if request.auto_finish:
                        hks = hooks.get('request_finished')
                        if hks:
                            # Make sure the request_finished handler always gets
                            # an instance of Response. This way, it's always
                            # possible for it to be changed without taking
                            # return values.
                            if not isinstance(output, Response):
                                if isinstance(output, tuple):
                                    out = Response(*output)
                                else:
                                    out = Response(output)

                            for hf in hks:
                                hf(request, output)

                    return output

                except HTTPException as err:
                    request._rule_headers = None
                    request._rule_content_type = None

                    err_handler = getattr(self, "handle_%d" % err.status, None)
                    if err_handler:
                        return err_handler(request, err)
                    else:
                        return error(err.message, err.status, err.headers,
                                     request=request)
                except HTTPTransparentRedirect as err:
                    request._rule_headers = None
                    request._rule_content_type = None

                    request.url = err.url
                    request._parse_url()
                    return self.route_request(request)
                except Exception as err:
                    request._rule_headers = None
                    request._rule_content_type = None

                    return self.handle_500(request, err)

        if available_methods:
            if request.method == 'OPTIONS':
                return '', 200, {'Allow': ', '.join(available_methods)}
            else:
                return error(
                    "The method %s is not allowed for %r." % (method, path),
                    405, {'Allow': ', '.join(available_methods)}
                )

        elif self.fix_end_slash:
            # If there are no matching routes, and the path doesn't end with a
            # slash, try adding the slash.
            if not path[-1] == "/":
                path += "/"
                matcher += "/"
                for dmn, dkey, rules in self._route_list:
                    if ':' in dmn:
                        if not request.host.lower().endswith(dmn):
                            continue
                    elif not domain.endswith(dmn):
                        continue

                    for rule, regex, rkey, name, method_table, names, namegen, \
                            converters in rules:
                        if not path.startswith(rule):
                            continue
                        if regex.match(matcher):
                            if request.query:
                                return redirect("%s?%s" %
                                                (path, request.query))
                            else:
                                return redirect(path)

        return self.handle_404(request, None)

    def parse_output(self, result):
        """ Process the output of :meth:`Application.route_request`. """
        request = self.request

        if not request.auto_finish or request._finish is not None:
            return

        status = None

        if isinstance(result, Response):
            body = result.body
            status = result.status
            headers = result.headers

        elif isinstance(result, tuple):
            if len(result) == 3:
                body, status, headers = result
            else:
                body, status = result
                headers = HTTPHeaders()
                
        else:
            body = result
            headers = HTTPHeaders()

        # If we don't have a body, use a 204.
        if status is None:
            if body is None:
                status = 204
            else:
                status = 200

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

        # Determine if we're sending a body.
        send_body = request.method.upper() != 'HEAD' and status not in NO_BODY_CODES

        # Convert the body to something that we can send.
        if send_body:
            # Use the rule content-type.
            if request._rule_content_type and not 'Content-Type' in headers:
                headers['Content-Type'] = request._rule_content_type

            try:
                body = body.to_html()
                if not 'Content-Type' in headers:
                    headers['Content-Type'] = 'text/html'
            except AttributeError:
                pass

            # Set a Content-Type header if there isn't one already.
            if not 'Content-Type' in headers:
                if isinstance(body, basestring) and body[:5].lower() in \
                        ('<html', '<!doc'):
                    headers['Content-Type'] = 'text/html'
                elif isinstance(body, (tuple, list, dict)):
                    headers['Content-Type'] = 'application/json'
                else:
                    headers['Content-Type'] = 'text/plain'

            if isinstance(body, unicode):
                encoding = headers['Content-Type']
                if 'charset=' in encoding:
                    before, sep, enc = encoding.partition('charset=')
                else:
                    before = encoding
                    sep = '; charset='
                    enc = 'UTF-8'

                body = body.encode(enc)
                headers['Content-Type'] = before + sep + enc

            elif isinstance(body, (tuple, list, dict)):
                try:
                    body = json.dumps(body, cls=self.json_encoder)
                except Exception as err:
                    body, status, headers = self.handle_500(request, err)
                    body = body.encode('utf-8')
                    headers['Content-Type'] = 'text/html; charset=UTF-8'

            elif body is None:
                body = ''

            elif not isinstance(body, str):
                body = str(body)

            # More headers!
            if not 'Content-Length' in headers:
                headers['Content-Length'] = len(body)

        else:
            # We're not allowed to send the body, so strip out any headers about
            # the content of the body.
            if 'Content-Length' in headers:
                del headers['Content-Length']

            if 'Content-Type' in headers:
                del headers['Content-Type']

            if 'Transfer-Encoding' in headers:
                del headers['Transfer-Encoding']

        # Send the response.
        request.send_status(status)
        request.send_headers(headers)

        if send_body:
            request.write(body)

        request.finish()


###############################################################################
# Private Helper Functions
###############################################################################

def _get_runner(func, converters, auto404):
    def view_runner(request):
        request.__func_module = func.__module__
        match = request.match

        if not converters:
            return func(request)

        try:
            # We have to get a bit fancy here, since a single converter can take
            # multiple values.
            i = 0
            out = []
            values = match.groups()

            for converter in converters:
                groups = converter.capture_groups
                out.append(converter(request, *values[i:i+groups]))
                i += groups

            request._converted_match = out

        except HTTPException as err:
            raise err
        except Exception as err:
            raise HTTPException(400, str(err))

        if auto404:
            all_or_404(*out)

        return func(request, *out)

    view_runner.wrapped_func = func
    return view_runner


def _rule_to_regex(rule):
    """
    Parse a rule and return a regular expression, as well as converters for
    value conversion and default values.
    """
    regex, converters, names, namegen, domain, path = "", [], [], "", "", ""

    # Make sure we have at least one /.
    if not '/' in rule:
        rule = '/' + rule

    in_domain = True

    # Handle the beginning of the string.
    if rule[0] == '.':
        regex += '[^./]+?'
    elif rule[0] == '/':
        regex += '[^/]+?'

    # Find the first <.
    ind = rule.find("<")
    if ind == -1 or RULE_PARSER.match(rule[ind:]) is None:
        if '/' in rule:
            domain, _, path = rule.partition('/')
            path = '/' + path
            regex += re.escape(domain) + "(?::\d+)?" + re.escape(path) + "$"
        else:
            regex += re.escape(rule) + "$"

        # There are no variables to match. Tough luck.
        return "^" + regex, tuple(), tuple(), rule, domain, path
    elif ind > 0:
        text = rule[:ind]
        rule = rule[ind:]

        if '/' in text:
            in_domain = False
            domain, _, path = text.partition('/')
            path = '/' + path
            regex += re.escape(domain) + "(?::\d+)?" + re.escape(path)
        else:
            regex += re.escape(text)
        namegen += text

    has_default = 0

    # Iterate through the matches.
    for match in RULE_PARSER.finditer(rule):
        converter, options, name, default, text = match.groups()
        names.append(name)

        if default is not None:
            has_default += 1
            if not in_domain:
                regex += "(?:"

        # If we're still in the domain, use a special converter that doesn't
        # match the period.
        if converter:
            converter = converter.lower()

        if converter == 'str':
            converter = 'string'
        if in_domain and (not converter or converter == 'string'):
            converter = 'domainpart'
        elif not in_domain and (not converter or converter == 'domainpart'):
            converter = 'string'

        converter = converter.strip()
        if not converter in CONVERTER_TYPES:
            raise ValueError("No such converter %r." % converter)

        # Make the converter.
        converter = CONVERTER_TYPES[converter](options, default)
        converters.append(converter)

        regex += converter.regex
        namegen += '%s' + text

        if in_domain and '/' in text:
            in_domain = False
            domain, _, path = text.partition('/')
            path = '/' + path
            regex += re.escape(domain) + "(?::\d+)?" + re.escape(path)

            if default:
                regex += ")?"

            while has_default > 0:
                regex = "(?:" + regex
                has_default -= 1
        else:
            regex += re.escape(text)
            if default and in_domain:
                regex += ")?"

    while has_default > 0:
        regex += ")?"
        has_default -= 1

    return "^" + regex + "$", tuple(converters), tuple(names), \
           namegen, domain, path


###############################################################################
# Public Helper Functions
###############################################################################

def abort(status=404, message=None, headers=None):
    """
    Raise a :class:`~pants.contrib.web.HTTPException` to display an error page.
    """
    raise HTTPException(status, message, headers)


def all_or_404(*args):
    """
    If any of the provided arguments aren't truthy, raise a ``404 Not Found``
    exception. This is automatically called for you if you set ``auto404=True``
    when using the route decorator.
    """
    all(args) or abort()


def error(message=None, status=None, headers=None, request=None, debug=None):
    """
    Return a very simple error page, defaulting to a ``404 Not Found`` error if
    no status code is supplied. Usually, you'll want to call :func:`abort` in
    your code, rather than error(). Usage::

        return error(404)
        return error("Some message.", 404)
        return error("Blah blah blah.", 403, {'Some-Header': 'Fish'})
    """
    if request is None:
        request = Application.current_app.request

    if status is None:
        if isinstance(message, (int, long)):
            status, message = message, None
        else:
            status = 404

    status_text = None
    if isinstance(status, basestring):
        status, _, status_text = status.partition(' ')
        status = int(status)
    if not status_text:
        status_text = HTTP.get(status, "Unknown Error")

    if not headers:
        headers = {}

    if message is None:
        message = HTTP_MESSAGES.get(status, u"An unknown error has occurred.")
        values = request.__dict__.copy()
        values['url'] = decode(urllib.unquote(values['url']))
        message = message.format(**values)

    if status in HAIKUS:
        haiku = u'<div class="haiku">%s</div>' % HAIKUS[status]
    else:
        haiku = u""

    if not message[0] == u"<":
        message = u"<p>%s</p>" % message

    if debug is None:
        debug = Application.current_app and Application.current_app.debug

    if debug:
        debug = u"%0.3f ms" % (1000 * request.time)
    else:
        debug = u""

    result = ERROR_PAGE.safe_substitute(
        status=status,
        status_text=status_text,
        status_text_nbsp=status_text.replace(u" ", u"&nbsp;"),
        haiku=haiku,
        content=message,
        scheme=request.scheme,
        host=request.host,
        debug=debug
    )

    return result, status, headers


def redirect(url, status=302, request=None):
    """
    Construct a ``302 Found`` response to instruct the client's browser to
    redirect its request to a different URL. Other codes may be returned by
    specifying a status.

    =========  ========  ============
    Argument   Default   Description
    =========  ========  ============
    url                  The URL to redirect the client's browser to.
    status     ``302``   *Optional.* The status code to send with the response.
    =========  ========  ============
    """
    if isinstance(url, unicode):
        url = url.encode('utf-8')

    return error(
        'The document you have requested is located at <a href="%s">%s</a>.' % (
            url, url), status, {'Location': url}, request=request)

def url_for(name, *values, **kw_values):
    """
    Generates a URL for the route with the given name. You may give either an
    absolute name for the route or use a period to match names relative to the
    current route. Multiple periods may be used to traverse up the name tree.

    Passed arguments will be used to construct the URL. Any unknown keyword
    arguments will be appended to the URL as query arguments. Additionally,
    there are several special keyword arguments to customize
    ``url_for``'s behavior.

    ==========  ========  ============
    Argument    Default   Description
    ==========  ========  ============
    _anchor     None      *Optional.* An anchor string to be appended to the URL.
    _doseq      True      *Optional.* The value to pass to :func:`urllib.urlencode`'s ``doseq`` parameter for building the query string.
    _external   False     *Optional.* Whether or not a URL is meant for external use. External URLs never have their host portion removed.
    _scheme     None      *Optional.* The scheme of the link to generate. By default, this is set to the scheme of the current request.
    ==========  ========  ============
    """

    if '_request' in kw_values:
        request = kw_values.pop('_request')
    else:
        app = Application.current_app
        if not app or not app.request:
            raise RuntimeError("Called url_for outside of a request.")
        request = app.request

    # Handle periods, which are for moving up the module table.
    if name[0] == '.':
        # Count and remove the periods.
        count = len(name)
        name = name.lstrip('.')
        count = count - len(name)

        # Now, build a list of route names, and pop one item off for every
        # period we've counted.
        mod_name = request.route_name.split('.')
        if count >= len(mod_name):
            del mod_name[:]
        else:
            del mod_name[len(mod_name) - count:]

        mod_name.append(name)
        name = '.'.join(mod_name)

    if not name in app._name_table:
        raise KeyError("Cannot find request handler with name %r." % name)

    rule_table = app._name_table[name]
    names, namegen, converters = rule_table[-3:]

    data = []
    values = list(values)

    for i in xrange(len(names)):
        name = names[i]

        if name in kw_values:
            val = kw_values.pop(name)
        elif values:
            val = values.pop(0)
        elif converters[i].default is not None:
            val = NoValue
        else:
            raise ValueError("Missing required value %r." % name)

        # Process the data.
        if val is NoValue:
            data.append(converters[i].default)
        else:
            data.append(converters[i].encode(request, val))

    # If we still have values, we were given too many.
    if values:
        raise ValueError("Too many values to unpack.")

    # Generate the string.
    out = namegen % tuple(data)

    dmn, sep, pth = out.partition("/")
    out = dmn + sep + urllib.quote(pth)

    if '_external' in kw_values:
        if kw_values['_external'] and out[0] == '/':
            out = request.host + out
        elif not kw_values['_external'] and out[0] != '/':
            _, _, out = out.partition('/')
            out = '/' + out
        del kw_values['_external']
    else:
        if not ":" in out and out.lower().startswith(request.hostname.lower()):
            out = out[len(request.hostname):]
        elif out.lower().startswith(request.host.lower()):
            out = out[len(request.host):]

    if '_scheme' in kw_values:
        if not out[0] == "/":
            out = "%s://%s" % (kw_values['_scheme'], out)
        elif request.scheme.lower() != kw_values['_scheme'].lower():
            out = "%s://%s%s" % (kw_values['_scheme'], request.host, out)
        del kw_values['_scheme']
    else:
        if not out[0] == "/":
            out = '%s://%s' % (request.scheme, out)

    # Remove the anchor before adding query string variables.
    anchor = kw_values.pop('_anchor', None)

    # Build the query
    if kw_values:
        out += '?%s' % urllib.urlencode(kw_values, doseq=kw_values.pop('_doseq', True))

    if anchor:
        out += '#' + anchor

    return out
