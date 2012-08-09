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
import os
import re
import string
import urllib

from datetime import datetime, timedelta

from pants.http import date, HTTP, SERVER, SERVER_URL

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

if os.name == 'nt':
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

# Regular expressions used for various types.
REGEXES = {
    int     : r'(-?\d+)',
    float   : r'(-?\d+(?:\.\d+)?)',
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

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# The Console JS
try:
    with open(os.path.join(DATA_DIR, "console.js"), "rb") as f:
        CONSOLE_JS = f.read()
except IOError:
    log.debug("Unable to load pants.web console JS from %r." % DATA_DIR)
    CONSOLE_JS = ""

# The Main CSS
try:
    with open(os.path.join(DATA_DIR, "main.css"), "rb") as f:
        MAIN_CSS = f.read()
except IOError:
    log.debug("Unable to load pants.web main CSS from %r." % DATA_DIR)
    MAIN_CSS = ""

# The Directory CSS
try:
    with open(os.path.join(DATA_DIR, "directory.css"), "rb") as f:
        DIRECTORY_CSS = f.read()
except IOError:
    log.debug("Unable to load pants.web directory CSS from %r." % DATA_DIR)
    DIRECTORY_CSS = ""

# The Images
IMAGES = {}
for name in ('audio', 'document', 'folder', 'image', 'video', 'zip'):
    try:
        with open(os.path.join(DATA_DIR, "%s.png" % name), "rb") as f:
            IMAGES[name] = base64.b64encode(f.read())
    except IOError:
        log.debug("Unable to load pants.web icon %r from %r." %
                    (name, DATA_DIR))

# Insert the images.
DIRECTORY_CSS = string.Template(DIRECTORY_CSS).safe_substitute(**IMAGES)

# The Main Template
try:
    with open(os.path.join(DATA_DIR, "main.html"), "rb") as f:
        PAGE = f.read()
except IOError:
    log.debug("Unable to load pants.web page template from %r." % DATA_DIR)
    PAGE = u"""<!DOCTYPE html>
<title>$title</title>
$content
<hr>
<address><a href="$server_url">$server</a> at
<a href="$schema://$host">$schema://$host</a></address>"""

# Fill up the template a bit.
PAGE = string.Template(PAGE).safe_substitute(
                                css=MAIN_CSS,
                                server_url=SERVER_URL,
                                server=SERVER)

PAGE = re.sub(">\s+<", "><", PAGE, flags=re.DOTALL)
PAGE = string.Template(PAGE)

# The Directory Template
try:
    with open(os.path.join(DATA_DIR, "directory.html"), "rb") as f:
        DIRECTORY_PAGE = PAGE.safe_substitute(
                                title="Index of $path",
                                content=f.read(),
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
    with open(os.path.join(DATA_DIR, "entry.html"), "rb") as f:
        DIRECTORY_ENTRY = f.read()
except IOError:
    DIRECTORY_ENTRY = '<tr><td><a class="icon $cls" href="$uri">$name</a>' + \
                      '</td><td>$size</td><td>$modified</td></tr>'

DIRECTORY_ENTRY = string.Template(DIRECTORY_ENTRY)

# The Error Template
try:
    with open(os.path.join(DATA_DIR, "error.html"), "rb") as f:
        ERROR_PAGE = PAGE.safe_substitute(
                            title="$status $status_text",
                            content=f.read(),
                            extra_css=u'')
except IOError:
    log.warning("Unable to load pants.web error template from %r." % DATA_DIR)
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
