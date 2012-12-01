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

###############################################################################
# Imports
###############################################################################

import base64
import logging
import re
import string
import sys

from pants.http.utils import HTTP, SERVER, SERVER_URL


try:
    from pkg_resources import resource_string
except ImportError:
    def resource_string(*args):
        raise IOError("pkg_resources not available.")

###############################################################################
# Logging
###############################################################################

log = logging.getLogger("pants.web")

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

if sys.platform.startswith('win'):
    HAIKUS[500] = (u'Yesterday it worked.<br>'
        u'Today, it is not working.<br>'
        u'Windows is like that.')

HTTP_MESSAGES = {
    401: u'You must sign in to access this page.',
    403: u'You do not have permission to view this page.',
    404: u'The page at <code>{uri}</code> cannot be found.',
    500: u'The server encountered an internal error and cannot display '
         u'this page.'
}

# Formats for _parse_date to use.
DATE_FORMATS = (
    "%a, %d %b %Y %H:%M:%S %Z",
    "%A, %d-%b-%y %H:%M:%S %Z",
    "%a %b %d %H:%M:%S %Y",
    )

###############################################################################
# Resources
###############################################################################

# The Console JS
try:
    CONSOLE_JS = resource_string("pants.web", "data/console.js")
except IOError:
    # This message is commented out because the console JS isn't actually
    # *used* yet in the code, and can be safely ignored.
    # log.debug("Unable to load pants.web console JS from %r." % DATA_DIR)
    CONSOLE_JS = ""

# The Main CSS
try:
    MAIN_CSS = resource_string("pants.web", "data/main.css")
except IOError:
    log.debug("Unable to load pants.web main CSS.")
    MAIN_CSS = ""

# The Directory CSS
try:
    DIRECTORY_CSS = resource_string("pants.web", "data/directory.css")
except IOError:
    log.debug("Unable to load pants.web directory CSS.")
    DIRECTORY_CSS = ""

# The Images
IMAGES = {}
for name in ('audio', 'document', 'folder', 'image', 'video', 'zip'):
    try:
        IMAGES[name] = base64.b64encode(resource_string("pants.web",
                                                        "data/%s.png" % name))
    except IOError:
        log.debug("Unable to load pants.web icon %r." % name)

# Insert the images.
DIRECTORY_CSS = string.Template(DIRECTORY_CSS).safe_substitute(**IMAGES)

# The Main Template
try:
    PAGE = resource_string("pants.web", "data/main.html")
except IOError:
    log.debug("Unable to load pants.web page template.")
    PAGE = u"""<!DOCTYPE html>
<title>$title</title>
$content
<hr>
<address><a href="$server_url">$server</a> at
<a href="$scheme://$host">$scheme://$host</a></address>"""

# Fill up the template a bit.
PAGE = string.Template(PAGE).safe_substitute(
                                css=MAIN_CSS,
                                server_url=SERVER_URL,
                                server=SERVER)

PAGE = re.compile(">\s+<", flags=re.DOTALL).sub("><", PAGE)
PAGE = string.Template(PAGE)

# The Directory Template
try:
    DIRECTORY_PAGE = PAGE.safe_substitute(
                            title="Index of $path",
                            content=resource_string("pants.web",
                                                    "data/directory.html"),
                            extra_css=DIRECTORY_CSS
                            )
except IOError:
    DIRECTORY_PAGE = PAGE.safe_substitute(
                            title="Index of $path",
                            content="""<h1>Index of $path</h1>
$go_up
<table><thead><tr><th>Name</th><th>Size</th><th>Last Modified</th></tr></thead>
$content
</table>""",
                            extra_css=DIRECTORY_CSS
                            )

DIRECTORY_PAGE = string.Template(DIRECTORY_PAGE)

# Directory Entry Template
try:
    DIRECTORY_ENTRY = resource_string("pants.web", "data/entry.html")
except IOError:
    DIRECTORY_ENTRY = '<tr><td><a class="icon $cls" href="$uri">$name</a>' + \
                      '</td><td>$size</td><td>$modified</td></tr>'

DIRECTORY_ENTRY = string.Template(DIRECTORY_ENTRY)

# The Error Template
try:
    ERROR_PAGE = PAGE.safe_substitute(
                        title="$status $status_text",
                        content=resource_string("pants.web", "data/error.html"),
                        extra_css=u'')
except IOError:
    log.warning("Unable to load pants.web error template.")
    ERROR_PAGE = PAGE.safe_substitute(
                        title="$status $status_text",
                        extra_css=u'',
                        content=u"""<h1>$status $status_text</h1>
$content""")

ERROR_PAGE = string.Template(ERROR_PAGE)


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
        super(HTTPException, self).__init__(status, message, headers)

    def __str__(self):
        return "%d %s [message=%r, headers=%r]" % \
            (self.status, HTTP.get(self.status, ''), self.args[1], self.args[2])

    def __repr__(self):
        return "HTTPException(status=%r, message=%r, headers=%r)" % self.args

    @property
    def status(self):
        return self.args[0]

    @property
    def message(self):
        return self.args[1]

    @property
    def headers(self):
        return self.args[2]


class HTTPTransparentRedirect(Exception):
    """
    Raising an instance of HTTPTransparentRedirect will cause the Application
    to silently redirect a request to a new URI.
    """
    def __init__(self, uri):
        super(HTTPTransparentRedirect, self).__init__(uri)

    def __str__(self):
        return "uri=%r" % self.args[0]

    def __repr__(self):
        return "%s(uri=%r)" % (self.__class__.__name__, self.args[0])

    @property
    def uri(self):
        return self.args[0]


###############################################################################
# Private Helper Functions
###############################################################################

_encodings = ('utf-8','iso-8859-1','cp1252','latin1')
def decode(text):
    for enc in _encodings:
        try:
            return text.decode(enc)
        except UnicodeDecodeError:
            continue
    else:
        return text.decode('utf-8','ignore')
