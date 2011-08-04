###############################################################################
#
# Copyright 2011 Pants Developers (see AUTHORS.txt)
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

###############################################################################
# Imports
###############################################################################

import base64
import inspect
import logging
import mimetypes
import os
import re
import time
import traceback
import urllib

from datetime import datetime, timedelta
from pants import __version__ as pants_version
from http import CRLF, HTTP, HTTPServer, HTTPRequest, SERVER, SERVER_URL, date

try:
    import simplejson as json
except ImportError:
    import json

__all__ = ('Application', 'HTTPException', 'HTTPTransparentRedirect', 'abort',
    'all_or_404', 'error', 'redirect', 'url_for', 'HTTPServer', 'FileServer')

###############################################################################
# Cross Platform Hidden File Detection
###############################################################################

def _is_hidden(file, path):
    return file.startswith(u'.')

if os.name == 'nt':
    try:
        import win32api, win32con
        def _is_hidden(file, path):
            if file.startswith(u'.'):
                return True
            file = os.path.join(path, file)
            try:
                if win32api.GetFileAttributes(file) & win32con.FILE_ATTRIBUTE_HIDDEN:
                    return True
            except Exception:
                return True
            return False
    except ImportError:
        pass

###############################################################################
# Logging
###############################################################################

log = logging.getLogger(__name__)

###############################################################################
# Constants
###############################################################################

HAIKUS = {
    400: u'Something you entered<br>'
         u'transcended parameters.<br>'
         u'So much is unknown.',

    401: u'To access this page,<br>'
         u'one must know oneself; but then:<br>'
         u'inform the server.',

    403: u'Unfortunately,<br>'
         u'permissions insufficient.<br>'
         u'This, you cannot see.',

    404: u'You step in the stream,<br>'
         u'But the water has moved on.<br>'
         u'This page is not here.',

    410: u'A file that big?<br>'
         u'It might be very useful.<br>'
         u'But now it is Gone.',

    413: u'Out of memory.<br>'
         u'We wish to hold the whole sky,<br>'
         u'But we never will.',

    418: u'You requested coffee,<br>'
         u'it is neither short nor stout.<br>'
         u'I am a teapot.',

    500: u'Chaos reigns within.<br>'
         u'Reflect, repent, and reboot.<br>'
         u'Order shall return.'
}

if os.name == 'nt':
    HAIKUS[500] = (u'Yesterday it worked.<br>'
        u'Today, it is not working.<br>'
        u'Windows is like that.')

HTTP_MESSAGES = {
    401: u'You must sign in to access this page.',
    403: u'You do not have permission to view this page.',
    404: u'The page at <code>%(uri)s</code> cannot be found.',
    500: u'The server encountered an internal error and cannot display '
         u'this page.'
}

IMAGES = {
    'audio'     : u"iVBORw0KGgoAAAANSUhEUgAAABIAAAAQCAYAAAAbBi9cAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAZpJREFUeNqsU01Lw0AQbdI0aVIVUiSlWKiV/gARiveC2ptehf4Rz+JJ0aM38ebJgzfvvQiWUhooqAeLYCkRUYRa8tHEN7IpIRS3ogsvuzs782Yz81YIgiDxH0P6ha/QbrdLvu/XgC1cIFWpVLZhd7lEpmlmXdetImgTwRuYl2Muc8DbT0SpZrN5huD65DqCkBBFkTAE3pFgCWaNR5RB9joFS5L0Ksvyg6qq97qum0CPJTrHLPJqlKFPPp8/KRQKDSw/IvgEsqw2AY/oOxNILjE9sWCbwSOCINZuXtf6wDPg81oqcs69WUhmIfq7IGMlEFut1u54PN6HvYROXpMiphEJnU5n1bbtUziuwbER41VBcowzgzZY1yANZ9qvKSC5gOM6acTzvCppKDI00hLZQruiKDfR+oVEmWQyqYWOBOz7EZ14xWLxMJ1Od6FqV9O023K5fAD7aKJ8VovFwWCwY1nWnuM4K8h2l8vljgzDuMLZCyCTPoESsMCexSNgAU6USAXo7dCjnGcK7jEdjVhhZaZ4mQlzGJLQ+BJgAITfplvWq5n7AAAAAElFTkSuQmCC",
    'document'  : u"iVBORw0KGgoAAAANSUhEUgAAABIAAAAQCAYAAAAbBi9cAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAS1JREFUeNpi/P//PwM1AAsan+306dPngYZr4dPEyMh4zdTU1BDI/IXLIF4g1mJiYgIpBgsguxjEhvK1oGrf4jKIE0QoKCjUi4iI3AaxX79+rfXw4cMaqEvAGGoYJz6vgZ1x//79RiCGuwpmCFp4MuIzCAykpaXLpaSkjkNdZAh00URSAxts65MnTzqBGEUcFG4kGQQLB2RvoVtElEEgoKKiUiEgIPAIpA/dnhcvXug/fvy4nCiDbt++3UFpggQDCQmJBllZ2X1A5j80KeZnz55ZP336tI0og4DObwBhil0kIyNTJikpeRLI/IsmxfTy5UvjR48e9RMV/cDA7AJiksIIPXH8Y2dnvwBKM/gwSA16+DGipQshINYAYilc3gaCP0D8DIhvAPE7mCBAgAEAx0h2pQytmCsAAAAASUVORK5CYII=",
    'folder'    : u"iVBORw0KGgoAAAANSUhEUgAAABIAAAAKCAYAAAC5Sw6hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAQ9JREFUeNqsUT2LwkAQvd3EaDDIESxiaQqLgCDk59z9Gu9XWN8/sUzE0i4iNloEES3EZJP1jWRExK/Chbezszvzdt6M0Fp/fWKZN349iqItbIMcwzD+wjAc4qheEUnakiRpxXH8n6ZpVwjRAM6PqPYHxn63IlkURR9Jv5ZljeiSicqy9FHh7kn+1nGcQRAES6pI+L6/llIeIKXJJPBJ2hl0vgXFAd+e51ExgrbSNM0MCbM8z+v3vmXySu7lDti4rkv901QRvRxBNFVKCQ58Z5rIWVWD0Dy1I/ozQbJiEvrxERnfQ8kSJr8ef4amjaG9A2QItK7lPFq2bcdMxFKIsAa0gV5lXzHtgTmwAA4nAQYAHA9ij4jhqJgAAAAASUVORK5CYII=",
    'icon'      : u"iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAQ5JREFUeNpiYWBg+M8wiAELiGhI9RuUjmuYvYmBiWGQA8YhEcVT995EETx96TrDgsIAhoT+DUQbBFJvnNEL5+uqK5OkF2SXqZ4mini2szrEgeiOQwaXb94ly+fE6kP2CMhudEeyYHMUqaFHKQDZBbMT3S1Y0yDMcaSE3tkZxShRTAqAhSLIkVjTILbQIjdqyU0OIEeiuwPkYJaBcBAxaRYWqoO+HByZDgRlGKoW1NR2GLm5maYOpKajhlQapEoI4qp3qVF0US2K0WsBalWVVI3i////M4LwaDk46sBRB446cNSBow4cdeCoA0cdOOrAUQeOOpDUThMpI6KU9vZIAVQdo4Z1mBgZGalmJkCAAQB+2V2B4VtJPwAAAABJRU5ErkJggg==",
    'image'     : u"iVBORw0KGgoAAAANSUhEUgAAABUAAAATCAYAAAB/TkaLAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAphJREFUeNqsVE1rE1EU7UxmEjMl0QYxIU4SRi2KH9CkBhWKC3FbRfAH+AfcuBH/hZsiCC66U1y4URcKFnQjk5As1G6UhsQmJCkGZpIxyeRjPDe8J9OhaSL44DBvHu/dc9+55z7BcZyF/z0kQM7n80/H4/E9WhAEYd8GTor1r9lsdhVTe56gi8DdWCz2IJlM5jEfe/YItVrtYrVafVKv11Xs25kVVASCdDASiXzBdxeoeLAbj8eL+FqdTudCoVBI0/5ZmfpwRWcwGOyxICNvpqQCyWLb9rXhcPgol8tVRVF8ibU3mUzmg/d2kks7CnZQ1RxOlEqlPrZarQoyvtzr9dZAcB8ELQR/C5LnIHhHBNK8FaXbjEajdiKR2MIvaX+k3+8r0PtSu92+CpLXxWLxYTqdfiz9i1UoKJNIpqCBQEDRNI3q8BkBz/l8vmXMAyI/0Gw2M1MKIJRKpTNIVAFIuz5g0hHgJ1CyLMsEoRYOh3UqPs9UME1zU9f1zRnJeklJa7tcLl8hdVRVpaADiRl73+ZpDTDlJgG44o7f79clSTIoqDiPlkRCaDQaN9F9z6DfDebxBbhhCXa8HgwGP+H3N6/+SFGU991udx0Zid4s+ZBleRu2OUHtTICVKijMC+zXSO9oNEqu6E2SwMJRfKlqKlXU3W2wywpsEyU7IVDXMIx1FOQkEbsfIhB+g5VuMWcMKVML+A7UqLtcQRfR7xs4fOwgKdyBcXWdxRnyjqKJweAex7F5C6a+zfWbNmAlatXuX+JD3tOJLGjF0/DwKrx4HgRnUelTpD13BXT9hfZcw+8OfxYP6yi6zg/YZA+v1DYlRICmS3DBCpGguMuhUOgVu+Vgnkzdz6Of/MigACFGIrHOqrAkJuOPAAMATZ5MP7rfmUUAAAAASUVORK5CYII=",
    'pants'     : u"iVBORw0KGgoAAAANSUhEUgAAAKAAAACgCAYAAACLz2ctAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAhxJREFUeNrs3U1OwkAYgGEHJyndsSKkm3I9E6/jNbgLN+gJum9Cp8q2CsbYH1qeZwmE6PBm5kuLMZxOp/cQwgtM7XA4pLjb7br9fp8sB1PLsixsLANzEiCziv0HjsejVWE0VVXZAXEEgwARIAIEASJAmN6364D96zRgB0SAIEDWPwMOfS+4P1Mu7V7z0n/+R/t93QvGEQwCRIAgQASIAGEWceg3fLbrZmvT/7zG/jztgDiCESA8xgz43+8Dmvmeaya0A+IIBgGyjhnQDMeYM77vA+IIBgEiQBAgAkSAIEAECAJEgCBABAgCRIAwimgJhuXvou2ACBAEiBlw/TNen5nPDogAQYCYAZfPTGcHRIAgQAQIAkSAIEAECAJEgCBAFsi94F/4vyl2QAQIjuDZbbfbEGMMVz893zRNulwuXUrJYglwhONiswllWX7ce835fH77itRiOYKH17Ztd+/568ZY17U1FeD0bpzKOIJFZwcEASJAECACBAEiQARoCRAgAgQBIkAQIAIEASJAECACBAEiQBAgAgQBIkAQIAIEASJAECACBAEiQBAgAgQBIkAQIAIEASJABAgCRIAgQAQIAkSAIEAECAJEgCBABAgCRIAgQAQIAkSAIEAECAJEgCBABAgCRIAgQAQIAkSAIEAEiABBgAgQBIgAQYAIEMYV+w9UVWVVBmQ97YAIEG4cwUVRpDzPXy3FMKzn33wKMACVd1AkmFTspgAAAABJRU5ErkJggg==",
    'video'     : u"iVBORw0KGgoAAAANSUhEUgAAABIAAAAPCAYAAADphp8SAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAe9JREFUeNqsU0tLAlEUdmZ8Tki5qHxvtV3gLgmC6C+06me06CG5KFBo0b6lEEI7qWVB5CJCXKuLFsngeyEjk4yOY98d7pWrGW0aOJxz73z3O+d+51xhOp3a/uOzUy+Wy+VDj8dTHI/H27quPzKAIAiW5xO6XK59OMUwjK1EIvGA2GRE8mQyuYU/crvd66PRyOb3+48jkcg74WDJ6vV6st1uZ2RZ3kCyTeCusf8E0yyibrcbRGavpmkFlhUkb3BNmMGqj0ajRRDZ+v1+nrvVCiMSJElykp1QKJQ2TdPVbDbPKMknKZtVxE4SHG7gbLVa51g6mUYoRhCJBtBHB5FJ9TA4EhuNjSU4gRfbErXT6WTZulqt7sXj8Tu+okqlckAChmONmCMiHwTOiqJoNBqN1GAwyJVKpdxim8lhgoM3IEHqBxEpE+3UoJdO1sFgMA0tXhBOKETCwR1FUTIMx4/E3NV6vd4lJ+gzXIPvWiAQeAXRDPfr1cLh8AWyyejGCSVZ2rUF3NKrDWDCX11bwM2Ipj6fT4XIQ2S4YT9qtVoyFovd8xWhk7skYDjo1GKTb6fBCGNf8Hq9Hw6HYwgdrlRVzaNr+cWuISGZ+lM8ERnzZJ219KLlrZJGwdx0UtdoJUP+rcE8dAD7sC/yNGBt4r8FGADC3BrRMDVuEAAAAABJRU5ErkJggg==",
    'zip'       : u"iVBORw0KGgoAAAANSUhEUgAAABIAAAAQCAYAAAAbBi9cAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAVdJREFUeNpi/P//PwM1AAsan+306dPngYZrIQtyc3Pr/fnzR+Lnz5+7QHxGRsZrpqamhkDmL1wG8QKxFlQxg5ycXMbfv3+/Pn369BJMDOoDLajat7gM4oRpAIHHjx/PANGysrKZQAMEnzx50gaTg6nFZRBcFUiDoqJi7u/fv/8ADZiO5iIUtdgMYkB20f379yeDaAUFhYR///6JPHr0qAfNMPwGgRSCNMjLyxcCDfj64MGDBaTGGgp4+PBhP4iWkZHJBFLgMMKllgmfQVJSUrUmJiZ2P378YAUGfBvQdQzkGrQPSD0ChtEekFeZmJjIMwgI3p06derSx48feQmFEU6DQN64c+eOvZmZmcHr169N8XmLYGC/e/duBtBFGDFKkkGwtISUkhnwZXB0r/1jZ2e/BNIMC1wYGxmD1IDUoliMZosQEGuAIgyPa/8A8TMgvgHyPUwQIMAA22WMeFl8he8AAAAASUVORK5CYII="
}

IMAGES['icon'] = base64.b64decode(IMAGES['icon'])

PAGE_CSS = u"""html, body { margin: 0; padding: 0; min-height: 100%%; }
body {
	font-family: Calibri,"Arial","Helvetica",sans-serif;
	background: #EEE;
	background-image: -webkit-gradient( linear, left bottom, left top,
		color-stop(0, #ccc), color-stop(0.5, #eee) );
    background-image: -moz-linear-gradient( center bottom, #ccc 0%%, #eee 50%% );
}

table.dir td,a { color: #666; }
h1, a:hover { color: #444; }

a { text-decoration: none; }
a:hover { text-decoration: underline; }

div.document,.left,pre,table.dir th:first-child,table.dir td:first-child {
    text-align: left; }
.thingy,.center,.footer { text-align: center; }
table.dir td,table.dir th,.right { text-align: right; }

table.dir td,table.dir th,.thingy > h1 { margin: 0; }
p { margin-bottom: 0; }
table.dir a,pre { display: block; }
pre {
	background: #ddd;
    background-color: rgba(199,199,199,0.5);
	text-align: left;
	border-radius: 5px;
	-moz-border-radius: 5px;
	padding: 5px;
}

table.dir { width:100%%; border-spacing: 0; }
table.dir td,table.dir th { padding: 2px 5px; }
table.dir td { border-top: 1px solid transparent; border-bottom: 1px solid transparent; }
table.dir tr:first-child td { border-top: none; }
table.dir tr:hover td { border-color: #ccc; }
table.dir td.noborder { border-color: transparent !important; }
table.dir th { border-bottom: 1px solid #ccc; }

.footer,.faint { color: #aaa; }
.footer .debug { font-size: 0.9em; font-family: Consolas,monospace; }
.haiku { margin-top: 20px; }
.haiku + p { color: #777; }
.spacer { padding-top: 60px; }
.column { max-width: 960px; min-width: 600px; margin: 0px auto; }
.footer { padding-top: 10px; }

a.icon { padding-left: 23px; background-position: left; }
a.icon,.thingy { background-repeat: no-repeat; }

a.folder { background-image: url("data:image/png;base64,%s"); }
a.document { background-image: url("data:image/png;base64,%s"); }
a.image { background-image: url("data:image/png;base64,%s"); }
a.zip { background-image: url("data:image/png;base64,%s"); }
a.audio { background-image: url("data:image/png;base64,%s"); }
a.video { background-image: url("data:image/png;base64,%s"); }

.thingy { background-color: #FFF; background-position: center; color: #000;
	border: 5px #ddd solid;
	-moz-border-radius: 25px;
	border-radius: 25px;
	padding: 50px;
	margin: 0 50px;
}""" % (IMAGES['folder'], IMAGES['document'], IMAGES['image'], IMAGES['zip'],
    IMAGES['audio'], IMAGES['video'])
PAGE_CSS = PAGE_CSS.replace('%','%%%%')

PAGE = u"""<!DOCTYPE html>
<html><head><title>%%s</title><style>%s</style></head><body>
<div class="column"><div class="spacer"></div><div class="thingy">
%%s
</div><div class="footer"><i><a href="%s">%s</a><br>%%%%s</i>
<div class="debug">%%%%s</div></div>
<div class="spacer"></div></div></body></html>""".replace('\n','') % (
    PAGE_CSS, SERVER_URL, SERVER)

DIRECTORY_PAGE = PAGE % (
    u'Index of %s',
    u"""<h1>Index of %s</h1>%s<table class="dir"><thead><tr>
<th style="width:50%%">Name</th><th>Size</th>
<th class="center" colspan="2">Last Modified</th></tr></thead>%s
</table>"""
    )

ERROR_PAGE = PAGE % (
    u'%d %s',
    u'<h1>%d<br>%s</h1>%s%s'
    )

# Regular expressions used for various types.
REGEXES = {
    int     : r'(-?\d+)',
    float   : r'(-?\d+(?:\.\d+)?)',
}

###############################################################################
# Special Exceptions
###############################################################################

class HTTPException(Exception):
    """
    Raising an instance of HTTPException will cause the Application to render
    an error page out to the client with the given
    `HTTP status code <http://en.wikipedia.org/wiki/List_of_HTTP_status_codes>`_,
    message, and any provided headers.

    This is, generally, preferable to allowing an exception of a different
    type to bubble up to the Application, which would result in a
    ``500 Internal Server Error`` page.

    The :func:`abort` helper function makes it easy to raise instances of
    this exception.

    =========  ============
    Argument   Description
    =========  ============
    status     *Optional.* The `HTTP status code <http://en.wikipedia.org/wiki/List_of_HTTP_status_codes>`_ to generate an error page for. If this isn't specified, a ``404 Not Found`` page will be generated.
    message    *Optional.* A text message to display on the error page.
    headers    *Optional.* A dict of extra HTTP headers to return with the rendered page.
    =========  ============
    """
    def __init__(self, status=404, message=None, headers=None):
        self.status = status
        self.message = message
        self.headers = headers

class HTTPTransparentRedirect(Exception):
    """
    Raising an instance of HTTPTransparentRedirect will cause the Application
    to silently redirect a request to a new URI.
    """
    def __init__(self, uri):
        self.uri = uri

###############################################################################
# Application Class
###############################################################################

class Application(object):
    """
    The Application class builds upon :class:`pants.contrib.http.HTTPServer`,
    adding support for request routing, additional error handling, and a
    degree of convenience that makes writing dynamic pages easier.

    Instances of Application are callable, and may be used as a HTTPServer's
    request handler.

    ===============  ============
    Argument         Description
    ===============  ============
    default_domain   *Optional.* The default domain to search for a route for if the request's Host does not exist.
    debug            *Optional.* If this is set to True, automatically generated ``500 Internal Server Error`` response pages will include information about the failed request, including a traceback of the exception that caused the page to be generated.
    ===============  ============
    """
    current_app = None

    def __init__(self, default_domain=None, debug=False):
        # Internal Stuff
        self._routes    = {}
        self._names     = {}

        self._routes[None] = {}

        # External Stuff
        self.default_domain = None
        self.debug = debug

    def run(self, port=None, host='', ssl_options=None):
        """
        This function exists for convenience, and when called creates a
        :class:`~pants.contrib.http.HTTPServer` instance with its request
        handler set to this application instance, calls
        :func:`~pants.contrib.http.HTTPServer.listen` on that HTTPServer, and
        finally, starts the Pants engine to process requests.

        ============  ============
        Argument      Description
        ============  ============
        port          *Optional.* The port to listen on. If this isn't specified, it will be either 80 or 443, depending on whether or not SSL options for the server have been provided.
        host          *Optional.* The host interface to listen on. If this isn't specified, listen on all interfaces.
        ssl_options   *Optional.* A dict of SSL options for the server. See :class:`pants.contrib.ssl.SSLServer` for more information.
        ============  ============
        """
        from pants import engine
        HTTPServer(self, ssl_options=ssl_options).listen(port, host)
        engine.start()

    ##### Route Management Methods ############################################

    def basic_route(self, rule, name=None, methods=['GET','HEAD']):
        """
        The basic_route decorator registers a route with the Application without
        holding your hand over it.

        It functions almost the same as the :func:`Application.route` decorator,
        but doesn't wrap the provided function with any argument handling code.
        Instead, you're provided with the request object and the the regex
        match object.

        Example Usage::

            @app.basic_route("/char/<char>")
            def my_route(request):
                char, = request.match.groups()
                return 'The character is %s!' % char

        That is, essentially, equivilent to::

            @app.route("/char/<char>/")
            def my_route(char):
                return 'The character is %s!' % char

        =========  ============
        Argument   Description
        =========  ============
        rule       The route rule to match for a request to go to the decorated function. See :func:`Application.route` for more information.
        name       *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods    *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        =========  ============
        """
        def decorator(func):
            if rule[0] != '/':
                domain, _, rule = rule.partition('/')
                rule = '/' + rule
            else:
                domain = None

            regex, arguments, names, namegen = _route_to_regex(rule)
            _regex = re.compile(regex)

            if name is None:
                name = "%s.%s" % (func.__module__, func.__name__)

            self._insert_route(_regex, func, domain, name, methods, names, namegen)
            return func
        return decorator

    def route(self, rule, name=None, methods=['GET','HEAD'], auto404=False):
        """
        The route decorator is used to register a new request handler with the
        Application instance. Example::

            @app.route("/")
            def hello_world():
                return "Hiya, Everyone!"

        Variables may be specified in the route *rule* by wrapping them with
        inequality signs (for example: ``<variable_name>``). By default, a
        variable part accepts any character except a slash (``/``) and returns
        a string value. However, you may specify a specific type to be returned
        by using the format ``<type:name>``, where type is the name of a
        callable in the pants.contrib.web namespace that accepts a single
        string as its argument, and returns a value. Built-in types, such as
        int and float, work well for this. Example::

            @app.route("/user/<int:id>/")
            def user(id):
                return "Hi, user %d!" % id

        The ``id`` is automatically converted into an integer for you, and as
        an added bonus, your function is never even called if the provided
        value for ``id`` isn't a valid number.

        Request handlers are easy to write and can send their output to the
        client simply by returning a value, such as a string::

            @app.route("/")
            def hello_world():
                return "Hiya, Everyone!"

        The previous code would result in a `200 OK`` response, with a
        ``Content-Type`` header of ``text/plain``, and a ``Content-Length``
        header of ``15``. With, of course, the body ``Hiya, Everyone!``.

        If the returned string begins with ``<!DOCTYPE`` or ``<html``, it will
        be assumed that the response is of ``Content-Type: text/html``.

        If a unicode object is returned, rather than a simple string, it will
        be automatically encoded and an encoding argument will be added to the
        ``Content-Type`` header.

        If a dictionary is returned, it will be automatically converted to a
        string of `JSON <http://en.wikipedia.org/wiki/JSON>`_ and the
        ``Content-Type`` header will be set to ``application/json``.

        If any other object is returned, it will be converted to a string
        via ``str()`` before any content headers are set. The exception to this
        is that, if the object has a ``__html__`` method, that method will be
        called rather than ``str()``, and the ``Content-Type`` will be
        automatically assumed to be ``text/html``, regardless of the actual
        content of the string.

        A tuple of ``(body, status)`` or ``(body, status, headers)`` may be
        returned, rather than simply a body, to set the HTTP status code of
        the result and additional response headers. If provided, ``status``
        must be an integer, and ``headers`` must be a dict.

        The following example returns a page with the status code ``404 Not Found``::

            @app.route("/nowhere")
            def nowhere():
                return "This does not exist.", 404

        =========  ============
        Argument   Description
        =========  ============
        rule       The route rule to be matched for the decorated function to be used for handling a request.
        name       *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods    *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        auto404    *Optional.* If this is set to True, all response handler arguments will be checked for truthiness (True, non-empty strings, etc.) and, if any fail, a ``404 Not Found`` page will be rendered automatically.
        =========  ============
        """
        if callable(name):
            self._add_route(rule, name, None, methods, auto404)
            return

        def decorator(func):
            self._add_route(rule, func, name, methods, auto404)
            return func
        return decorator

    ##### Error Handlers ######################################################

    def handle_404(self, request, exception):
        if isinstance(exception, HTTPException):
            return error(exception.message, 404)
        return error(404)

    def handle_500(self, request, exception):
        log.exception('Error handling HTTP request: %s %%s' % request.method,
            request.uri)
        if not self.debug:
            return error(500)

        resp = u''.join([
            u"<h2>Traceback</h2>\n",
            u"<pre>%s</pre>\n" % traceback.format_exc(),
            u"<h2>Route</h2>\n<pre>",
            u"route name   = %r\n" % request.route_name,
            u"match groups = %r" % (request.match.groups(),),
            u"</pre>\n",
            u"<h2>HTTP Request</h2>\n",
            request.__html__(),
            ])

        return error(resp, 500)

    ##### The Request Handler #################################################

    def __call__(self, request):
        """
        This function is called when a new request is received, and calls both
        :func:`Application.handle_request` and :func:`Application.handle_output`
        to process the request.
        """
        Application.current_app = self
        self.request = request

        try:
            request.auto_finish = True
            self.handle_output(self.handle_request(request))
        finally:
            request.route = None
            request.match = None
            request.route_name = None

            Application.current_app = None
            self.request = None

    def handle_output(self, result):
        """ Process the output of handle_request. """
        request = self.request

        if not request.auto_finish or result is None or \
                request._finish is not None:
            if request.auto_finish and request._finish is None:
                request.finish()
            return

        status = 200
        if type(result) is tuple:
            if len(result) == 3:
                body, status, headers = result
            else:
                body, status = result
                headers = {}
        else:
            body = result
            headers = {}

        # Set a Content-Type header if there isn't already one.
        if not 'Content-Type' in headers:
            if (isinstance(body, basestring) and
                    body[:5].lower() in ('<html','<!doc')) or \
                    hasattr(body, '__html__'):
                headers['Content-Type'] = 'text/html'
            elif isinstance(body, dict):
                headers['Content-Type'] = 'application/json'
            else:
                headers['Content-Type'] = 'text/plain'

        # Convert the body to something sendable.
        try:
            body = body.__html__()
        except AttributeError:
            pass

        if isinstance(body, unicode):
            encoding = headers['Content-Type']
            if 'charset=' in encoding:
                before, sep, enc = encoding.partition('charset=')
            else:
                before = encoding
                sep = '; charset='
                enc = 'UTF-8'

            body = body.encode(enc)
            headers['Content-Type'] = '%s%s%s' % (before, sep, enc)

        elif isinstance(body, dict):
            try:
                body = json.dumps(body)
            except Exception, e:
                body, status, headers = self.handle_500(request, e)
                body = body.encode('utf-8')
                headers['Content-Type'] = 'text/html; charset=UTF-8'

        elif not isinstance(body, str):
            body = str(body)

        # More headers!
        headers['Content-Length'] = len(body)
        if not 'Date' in headers:
            headers['Date'] = date(datetime.utcnow())
        if not 'Server' in headers:
            headers['Server'] = SERVER

        # Send the response.
        request.send_status(status)
        request.send_headers(headers)

        if request.method == 'HEAD':
            request.finish()
            return

        request.write(body)
        request.finish()

    def handle_request(self, request):
        path = request.path

        # Domain Matching
        if len(self._routes) == 1:
            domain = None
        else:
            if request.host in self._routes:
                domain = request.host
            else:
                domain = '.' + request.host.partition('.')[2]
                if not domain in self._routes and ':' in request.host:
                    domain = request.host.rpartition(':')[0]
                    if not domain in self._routes:
                        domain = '.' + domain.partition('.')[2]
                if not domain in self._routes:
                    domain = self.default_domain

        for route in self._routes[domain]:
            match = route.match(path)
            if match is None:
                continue

            # Process this route.
            func, name, methods = self._routes[domain][route][:3]

            request.route = route
            request.match = match
            request.route_name = name

            if request.method not in methods:
                return error(
                    'The method %s is not allowed for %r.' % (
                        request.method, path), 405, {
                            'Allow': ', '.join(methods)
                        })
            else:
                try:
                    return func(request)
                except HTTPException, e:
                    if hasattr(self, 'handle_%d' % e.status):
                        return getattr(self, 'handle_%d' % e.status)(request, e)
                    else:
                        return error(e.message, e.status, e.headers)
                except HTTPTransparentRedirect, e:
                    request.uri = e.uri
                    request._parse_uri()
                    return self.handle_request(request)
                except Exception, e:
                    return self.handle_500(request, e)
            break
        else:
            # No matching routes.
            if not path.endswith('/'):
                p = '%s/' % path
                for route in self._routes[domain]:
                    if route.match(p):
                        if request.query:
                            return redirect('%s?%s' % (p,request.query))
                        else:
                            return redirect(p)

        return self.handle_404(request, None)

    ##### Internal Methods and Event Handlers #################################

    def _insert_route(self, route, handler, domain, name, methods, nms, namegen):
        if isinstance(route, basestring):
            route = re.compile(route)
        if not domain in self._routes:
            self._routes[domain] = {}
        self._routes[domain][route] = (handler, name, methods, nms, namegen)
        self._names[name] = route

    def _add_route(self, route, view, name=None, methods=['GET','HEAD'],
            auto404=False):
        """ See: Application.route """
        if name is None:
            if view is None:
                raise Exception('No name or view specified!')
            if hasattr(view, '__name__'):
                name = view.__name__
            elif hasattr(view, '__class__'):
                name = view.__class__.__name__
            else:
                raise NameError("Cannot find name for this route.")

        if not callable(view):
            raise Exception('View must be callable.')

        # Parse the route.
        if route[0] != '/':
            domain, _, route = route.partition('/')
            route = '/' + route
        else:
            domain = None

        regex, arguments, names, namegen = _route_to_regex(route)
        _regex = re.compile(regex)

        if not arguments:
            arguments = False

        try:
            args = inspect.getargspec(view).args
        except TypeError:
            args = inspect.getargspec(view.__call__).args[1:]

        if len(args) == 1 and args[0] == 'request':
            def view_runner(request):
                request.__viewmodule__ = view.__module__
                match = request.match
                try:
                    if arguments is False:
                        return view(request)

                    out = []
                    for val,type in zip(match.groups(), arguments):
                        if type is not None:
                            try:
                                val = type(val)
                            except Exception:
                                return error('Unable to parse data %r.' % val, 400)
                        out.append(val)

                    if auto404 is True:
                        all_or_404(*out)

                    request.arguments = out
                    return view(request)
                finally:
                    request.arguments = None

        else:
            def view_runner(request):
                request.__viewmodule__ = view.__module__
                match = request.match
                try:
                    try:
                        view.func_globals['request'] = request
                    except AttributeError:
                        view.__call__.func_globals['request'] = request
                    if arguments is False:
                        return view()

                    out = []
                    for val,type in zip(match.groups(), arguments):
                        if type is not None:
                            try:
                                val = type(val)
                            except Exception:
                                return error('Unable to parse data %r.' % val, 400)
                        out.append(val)

                    if auto404 is True:
                        all_or_404(*out)

                    return view(*out)
                finally:
                    try:
                        view.func_globals['request'] = None
                    except AttributeError:
                        view.__call__.func_globals['request'] = None

        view_runner.__name__ = name
        self._insert_route(_regex, view_runner, domain,
            "%s.%s" %(view.__module__,name), methods, names, namegen)

###############################################################################
# FileServer Class
###############################################################################

class FileServer(object):
    """
    The FileServer is a request handling class that, as it sounds, serves files
    to the client. It also supports the ``Content-Range`` header, HEAD requests,
    and last modified dates.

    ==========  ==============================  ============
    Argument    Default                         Description
    ==========  ==============================  ============
    path                                        The path to serve.
    blacklist   ``.py`` and ``.pyc`` files      *Optional.* A list of regular expressions to test filenames against. If a given file matches any of the provided patterns, it will not be downloadable and instead return a ``403 Unauthorized`` error.
    default     ``index.html``, ``index.htm``   *Optional.* A list of default files to be displayed rather than a directory listing if they exist.
    renderers   None                            *Optional.* A dictionary of methods for rendering files with a given extension into more suitable output, such as converting rST to HTML, or minifying CSS.
    ==========  ==============================  ============

    It attempts to serve the files as efficiently as possible, using the
    `sendfile <http://www.kernel.org/doc/man-pages/online/pages/man2/sendfile.2.html>`_
    system call when possible, and with proper use of ETags and other headers to
    minimize repetitive downloading.

    Using it is simple. It only requires a single argument: the path to serve
    files from. You can also supply a list of default files to check to serve
    rather than a file listing.

    When used with an Application, the FileServer is not created in the usual
    way with the route decorator, but rather with a method of the FileServer
    itself. Example::

        FileServer("/tmp/path").attach(app)

    If you wish to listen on a path other than ``/static/``, you can also use
    that when attaching::

        FileServer("/tmp/path").attach(app, "/files/")
    """
    def __init__(self, path, blacklist=[re.compile('.*\.pyc?$')],
            defaults=['index.html','index.htm'],
            renderers=None):
        # Make sure our path is unicode.
        if not isinstance(path, unicode):
            path = _decode(path)

        self.path = os.path.normpath(os.path.realpath(path))
        self.defaults = defaults
        self.renderers = renderers or {}

        # Build the blacklist.
        self.blacklist = []
        for bl in blacklist:
            if isinstance(bl, str):
                bl = re.compile(bl)
            self.blacklist.append(bl)

    def attach(self, app, path='/static/', domain=None):
        """
        Attach this fileserver to an application, bypassing the usual route
        decorator to ensure things are done right.

        =========  ===============  ============
        Argument   Default          Description
        =========  ===============  ============
        app                         The :class:`~pants.contrib.web.Application` instance to attach to.
        path       ``'/static/'``   *Optional.* The path to serve requests from.
        domain     None             *Optional.* The domain to serve requests upon.
        =========  ===============  ============
        """
        path = re.compile("^%s(.*)$" % re.escape(path))
        app._insert_route(path, self, domain, "FileServer", ['HEAD','GET'], None, None)

    def check_blacklist(self, path):
        """
        Check the given path to make sure it isn't blacklisted. If it is
        blacklisted, then raise an :class:`~pants.contrib.web.HTTPException`
        via :func:`~pants.contrib.web.abort`.

        =========  ============
        Argument   Description
        =========  ============
        path       The path to check against the blacklist.
        =========  ============
        """
        for bl in self.blacklist:
            if isinstance(bl, unicode):
                if bl in path:
                    abort(403)
            elif bl.match(path):
                abort(403)

    def __call__(self, request):
        """
        Serve a request.
        """

        try:
            path = request.match.group(1)
        except (AttributeError, IndexError):
            path = request.path

        # Conver the path to unicode.
        path = _decode(urllib.unquote(path))

        # Strip off a starting quote.
        if path.startswith('/') or path.startswith('\\'):
            path = path[1:]

        # Normalize the path.
        full_path = os.path.normpath(os.path.join(self.path, path))

        # Validate the request.
        if not full_path.startswith(self.path):
            abort(403)
        if not os.path.exists(full_path):
            abort(404)

        # Is this a directory?
        if os.path.isdir(full_path):
            # Check defaults.
            for f in self.defaults:
                full = os.path.join(full_path, f)
                if os.path.exists(full):
                    request.path = urllib.quote(full.encode('utf8'))
                    if hasattr(request, 'match'):
                        del request.match
                    return self.__call__(request)

            # Guess not. List it.
            if hasattr(request, 'match'):
                return self.list_directory(request, path)
            else:
                body, status, headers = self.list_directory(request, path)
                if isinstance(body, unicode):
                    body = body.encode('utf-8')
                headers['Content-Length'] = len(body)
                request.send_status(status)
                request.send_headers(headers)
                request.send(body)
                request.finish()
                return

        # Blacklist Checking.
        self.check_blacklist(full_path)

        # Try rendering the content.
        ext = os.path.basename(full_path).rpartition('.')[-1]
        if ext in self.renderers:
            f, mtime, size, type = self.renderers[ext](request, full_path)
        else:
            # Get the information for the actual file.
            f = None
            stat = os.stat(full_path)
            mtime = stat.st_mtime
            size = stat.st_size
            type = mimetypes.guess_type(full_path)[0]

        # If we don't have a type, text/plain it.
        if type is None:
            type = 'text/plain'

        # Generate a bunch of data for headers.
        modified = datetime.fromtimestamp(mtime)
        expires = datetime.utcnow() + timedelta(days=7)

        etag = '"%x-%x"' % (size, int(mtime))

        headers = {
            'Last-Modified' : date(modified),
            'Expires'       : date(expires),
            'Cache-Control' : 'max-age=604800',
            'Content-Type'  : type,
            'Date'          : date(datetime.utcnow()),
            'Server'        : SERVER,
            'Accept-Ranges' : 'bytes',
            'ETag'          : etag
        }

        do304 = False

        if 'If-Modified-Since' in request.headers:
            try:
                since = _parse_date(request.headers['If-Modified-Since'])
            except ValueError:
                since = None
            if since and since >= modified:
                do304 = True

        if 'If-None-Match' in request.headers:
            if etag == request.headers['If-None-Match']:
                do304 = True

        if do304:
            if f:
                f.close()
            request.auto_finish = False
            request.send_status(304)
            request.send_headers(headers)
            request.finish()
            return

        if 'If-Range' in request.headers:
            if etag != request.headers['If-Range'] and \
                    'Range' in request.headers:
                del request.headers['Range']

        last = size - 1
        range = 0, last
        status = 200

        if 'Range' in request.headers:
            if request.headers['Range'].startswith('bytes='):
                try:
                    val = request.headers['Range'][6:].split(',')[0]
                    start, end = val.split('-')
                except ValueError:
                    if f:
                        f.close()
                    abort(416)
                try:
                    if end and not start:
                        end = last
                        start = last - int(end)
                    else:
                        start = int(start or 0)
                        end = int(end or last)

                    if start < 0 or start > end or end > last:
                        if f:
                            f.close()
                        abort(416)
                    range = start, end
                except ValueError:
                    pass
                if range[0] != 0 or range[1] != last:
                    status = 206
                    headers['Content-Range'] = 'bytes %d-%d/%d' % (
                        range[0], range[1], size)

        # Set the content length header.
        if range[0] == range[1]:
            headers['Content-Length'] = 0
        else:
            headers['Content-Length'] = 1 + (range[1] - range[0])

        # Send the headers and status line.
        request.auto_finish = False
        request.send_status(status)
        request.send_headers(headers)

        # Don't send the body if this is head.
        if request.method == 'HEAD':
            if f:
                f.close()
            request.finish()
            return

        # Open the file and send it.
        if range[0] == range[1]:
            if f:
                f.close()
            request.finish()
            return

        if f is None:
            f = open(full_path, 'rb')

        if range[1] != last:
            length = 1 + (range[1] - range[0])
        else:
            length = 0

        def on_write():
            del request.connection.handle_write_file
            request.finish()

        request.connection.handle_write_file = on_write
        request.connection.write_file(f, nbytes=length, offset=range[0])

    def list_directory(self, request, path):
        """
        Generate a directory listing and return it.
        """

        # Normalize the path.
        full_path = os.path.normpath(os.path.join(self.path, path))

        # Get the URI, which is just request.path decoded.
        uri = _decode(urllib.unquote(request.path))
        if not uri.startswith(u'/'):
            uri = u'/%s' % uri
        if not uri.endswith(u'/'):
            return redirect(u'%s/' % uri)

        go_up = u''
        url = uri.strip(u'/')
        if url:
            go_up = u'<p><a href="..">Up to Higher Directory</a></p>'

        files = []
        dirs = []

        for p in sorted(os.listdir(full_path), key=unicode.lower):
            if _is_hidden(p, full_path):
                continue

            full = os.path.join(full_path, p)
            try:
                fp = full
                if os.path.isdir(full):
                    fp += '/'
                self.check_blacklist(fp)
            except HTTPException:
                continue

            stat = os.stat(full)
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime(
                u'<td class="right">%Y-%m-%d</td>'
                u'<td class="left">%I:%M:%S %p</td>'
                )

            if os.path.isdir(full):
                cls = u'folder'
                link = u'%s/' % p
                size = u'<span class="faint">Directory</span>'
                obj = dirs

            elif os.path.isfile(full):
                cls = 'document'
                ext = p[p.rfind('.')+1:]
                if ext in ('jpg','jpeg','png','gif','bmp'):
                    cls = 'image'
                elif ext in ('zip','gz','tar','7z','tgz'):
                    cls = 'zip'
                elif ext in ('mp3','mpa','wma','wav','flac','mid','midi','raw',
                        'mod','xm','aac','m4a','ogg','aiff','au','voc','m3u',
                        'pls','asx'):
                    cls = 'audio'
                elif ext in ('mpg','mpeg','mkv','mp4','wmv','avi','mov'):
                    cls = 'video'
                link = p
                size = _human_readable_size(stat.st_size)
                obj = files

            else:
                continue

            obj.append(
                u'<tr><td><a class="icon %s" href="%s%s">%s</a></td><td>%s'
                u'</td>%s</tr>' % (
                    cls, uri, link, p, size, mtime))

        if files or dirs:
            files = u''.join(dirs) + u''.join(files)
        else:
            files = (u'<tr><td colspan="4" class="noborder">'
                     u'<div class="footer center">'
                     u'This directory is empty.</div></td></tr>')

        if Application.current_app and Application.current_app.debug:
            rtime = u'%0.3f ms' % (1000 * request.time)
        else:
            rtime = u''

        return DIRECTORY_PAGE % (uri, uri, go_up, files, request.host, rtime), \
            200, {
                'Content-Type':'text/html; charset=utf-8'
            }

###############################################################################
# Private Helper Functions
###############################################################################

def path(st):
    return st
path.regex = "(.+?)"

def _get_thing(thing):
    if thing in globals():
        return globals()[thing]
    elif type(__builtins__) is dict and thing in __builtins__:
        return __builtins__[thing]
    elif hasattr(__builtins__, thing):
        return getattr(__builtins__, thing)
    return None

_route_parser = re.compile(r"<([^>]+)>([^<]*)")
def _route_to_regex(route):
    """ Parse a Flask-style route and return a regular expression, as well as
        a tuple of things for conversion. """
    regex, values, names, namegen = "", [], [], ""
    if not route.startswith("^/"):
        if route.startswith("/"):
            route = "^%s$" % route
        else:
            route = "^/%s$" % route

    # Find up to the first < and add it to regex.
    ind = route.find('<')
    if ind is -1:
        return route, tuple(), tuple(), route[1:-1]
    elif ind > 0:
        regex += route[:ind]
        namegen += route[:ind]
        route = route[ind:]

    # If the parser doesn't match, return.
    if not _route_parser.match(route):
        return regex+route, tuple(), tuple(), (regex+route)[1:-1]

    for match in _route_parser.finditer(route):
        group = match.group(1)
        if ':' in group:
            type, var = group.split(':', 1)
            thing = _get_thing(type)
            if not thing:
                raise Exception, "Invalid type declaration, %s" % type
            if hasattr(thing, 'regex'):
                regex += thing.regex
            elif thing in REGEXES:
                regex += REGEXES[thing]
            else:
                regex += "([^/]+)"
            values.append(thing)
            names.append(var)
        else:
            regex += "([^/]+)"
            values.append(None)
            names.append(group)
        namegen += "%s" + match.group(2)
        regex += match.group(2)

    return regex, tuple(values), tuple(names), namegen[1:-1]

_abbreviations = (
    (1<<50L, u' PB'),
    (1<<40L, u' TB'),
    (1<<30L, u' GB'),
    (1<<20L, u' MB'),
    (1<<10L, u' KB'),
    (1, u' B')
)
def _human_readable_size(size, precision=2):
    """ Convert a size to a human readable filesize. """
    if size == 0:
        return u'0 B'

    for f,s in _abbreviations:
        if size >= f:
            break

    ip, dp = `size/float(f)`.split('.')
    if int(dp[:precision]):
        return  u'%s.%s%s' % (ip,dp[:precision],s)
    return u'%s%s' % (ip,s)

_encodings = ('utf-8','iso-8859-1','cp1252','latin1')
def _decode(text):
    for enc in _encodings:
        try:
            return text.decode(enc)
        except UnicodeDecodeError:
            continue
    else:
        return text.decode('utf-8','ignore')

def _parse_date(text):
    return datetime(*time.strptime(text, "%a, %d %b %Y %H:%M:%S GMT")[:6])

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
    no status code is supplied. Usually, you'll want to call :func:`~pants.contrib.web.abort`
    in your code, rather than error(), to streamline the process of abandoning
    your code. Usage::

        return error(404)
        return error("Some message.", 404)
        return error("Blah blah blah.", 403, {'Some-Header':'Fish'})
    """
    if request is None:
        request = Application.current_app.request

    if status is None:
        if type(message) is int:
            status = message
            message = None
        else:
            status = 404

    if not status in HTTP:
        status = 404
    title = HTTP[status]
    if not headers:
        headers = {}

    if message is None:
        if status in HTTP_MESSAGES:
            dict = request.__dict__.copy()
            dict['uri'] = _decode(urllib.unquote(dict['uri']))
            message = HTTP_MESSAGES[status] % dict
        else:
            message = u"An unspecified error has occured."

    haiku = u''
    if status in HAIKUS:
        haiku = u'<div class="haiku">%s</div>' % HAIKUS[status]

    if not message.startswith(u'<'):
        message = u'<p>%s</p>' % message

    if debug is None:
        debug = Application.current_app and Application.current_app.debug

    if debug:
        time = u'%0.3f ms' % (1000 * request.time)
    else:
        time = u''

    result = ERROR_PAGE % (status, title, status, title.replace(u' ',u'&nbsp;'),
        haiku, message, request.host, time)

    return result, status, headers

def redirect(uri, status=302):
    """
    Construct a ``302 Found`` response to instruct the client's browser to
    redirect its request to a different URL. Other codes may be returned by
    specifying a status.

    =========  ========  ============
    Argument   Default   Description
    =========  ========  ============
    uri                  The URI to redirect the client's browser to.
    status     ``302``   *Optional.* The status code to send with the response.
    =========  ========  ============
    """
    url = uri
    if isinstance(url, unicode):
        url = uri.encode('utf-8')

    return error(
        'The document you have requested is located at <a href="%s">%s</a>.' % (
            uri, uri), status, {'Location':url})

def url_for(name, **values):
    """
    Generates a URL to the route with the given name. The name is relative to
    the module of the route function. Examples:

    ==============  ================  ================
    View's Module   Target Endpoint   Target Function
    ==============  ================  ================
    ``test``        ``index``         ``test.index``
    ``test``        ``.who``          The first ``who`` function in *any* module.
    ``test``        ``admin.login``   ``admin.login``
    ==============  ================  ================

    Any value provided to the function with an unknown key is appended to the
    generated URL as query arguments. For example, take the following route::

        @app.route("/user/<int:id>/")
        def user_page(id):
            pass

    Assuming ``url_for`` is used within the same module, the following examples
    will hold true::

        >>> url_for("user_page", id=12)
        '/user/12/'

        >>> url_for("user_page", id=12, section=3)
        '/user/12/?section=3'

        >>> url_for("user_page", id=12, _external=True)
        'http://www.example.com/user/12/'

    As demonstrated above, the ``_external`` parameter is special, and will
    result in the generation of a full URL, using the scheme and host provided
    by the current request.

    *Note:* This function has not yet been updated to properly make use of
    domains.
    """
    app = Application.current_app
    request = app.request

    if name.startswith('.'):
        # Find it in the first possible place.
        name = name[1:]
        for n in app._names:
            module, nm = n.split('.',1)
            if nm == name:
                name = n
                break
    elif not '.' in name:
        # Find it in this module.
        name = "%s.%s" % (request.__viewmodule__, name)

    if not name in app._names:
        raise NameError("Cannot find route %r." % name)

    route = app._names[name]
    names, namegen = app._routes[route][-2:]

    out = []
    for n in names:
        out.append(str(values[n]))
        del values[n]
    out = tuple(out)

    if len(out) == 1:
        out = namegen % out[0]
    else:
        out = namegen % out
    out = urllib.quote(out)

    if '_external' in values:
        if values['_external']:
            out = '%s://%s%s' % (request.protocol, request.host, out)
        del values['_external']

    if values:
        out += '?%s' % urllib.urlencode(values)

    return out
