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
</div><div class="footer"><i><a href="%s">%s</a><br><a class="faint" href="http://%%%%s/">%%%%s</a></i>
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

# Formats for _parse_date to use.
DATE_FORMATS = (
    "%a, %d %b %Y %H:%M:%S %Z",
    "%A, %d-%b-%y %H:%M:%S %Z",
    "%a %b %d %H:%M:%S %Y",
    )

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
