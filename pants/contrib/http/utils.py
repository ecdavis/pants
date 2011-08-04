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

import hashlib
import hmac
import logging
import mimetypes
import os

if os.name == 'nt':
    from time import clock as time
else:
    from time import time

from pants import callback, Connection, Server, __version__ as pants_version
from pants.engine import Engine
from pants.stream import Stream

###############################################################################
# Logging
###############################################################################

log = logging.getLogger('http')

###############################################################################
# Constants
###############################################################################

SERVER      = 'HTTPants (pants/%s)' % pants_version
SERVER_URL  = 'http://www.pantsweb.org/'

USER_AGENT = "HTTPants/%s" % pants_version

COMMA_HEADERS = ('Accept', 'Accept-Charset', 'Accept-Encoding',
    'Accept-Language', 'Accept-Ranges', 'Allow', 'Cache-Control', 'Connection',
    'Content-Encoding', 'Content-Language', 'Expect', 'If-Match',
    'If-None-Match', 'Pragma', 'Proxy-Authenticate', 'TE', 'Trailer',
    'Transfer-Encoding', 'Upgrade', 'Vary', 'Via', 'Warning',
    'WWW-Authenticate')

CRLF = '\r\n'
DOUBLE_CRLF = CRLF + CRLF

HTTP = {
    101: 'Switching Protocols',
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authorative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    306: 'No Longer Used',
    307: 'Temporary Redirect',
    400: 'Bad Request',
    401: 'Not Authorised',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Request Entity Too Large',
    414: 'Request URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Requested Range Not Satisfiable',
    417: 'Expectation Failed',
    418: "I'm a teapot",
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported'
}

class BadRequest(Exception):
    def __init__(self, message, code='400 Bad Request'):
        Exception.__init__(self, message)
        self.code = code

###############################################################################
# Support Functions
###############################################################################

def generate_signature(key, *parts):
    hash = hmac.new(key, digestmod=hashlib.sha1)
    for p in parts:
        hash.update(str(p))
    return hash.hexdigest()

def content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def encode_multipart(vars, files=None, boundary=None):
    """
    Encode a set of variables and/or files into a ``multipart/form-data``
    request body.

    =========  ============
    Argument   Description
    =========  ============
    vars       A dictionary of variables to encode.
    files      *Optional.* A dictionary of tuples of ``(filename, data)`` to encode.
    boundary   *Optional.* The boundary string to use when encoding, if for any reason the default string is unacceptable.
    =========  ============
    """

    if boundary is None:
        boundary = '-----pants-----PANTS-----pants$'

    out = []

    for k, v in vars.iteritems():
        out.append('--%s' % boundary)
        out.append(CRLF.join([
            'Content-Disposition: form-data; name="%s"' % k,
            '', str(v)]))
    if files:
        for k, (fn, v) in files.iteritems():
            out.append('--%s' % boundary)
            out.append(CRLF.join([
                'Content-Disposition: form-data; name="%s"; filename="%s"' % (
                    k, fn),
                'Content-Type: %s' % content_type(fn),
                '',
                str(v)]))

    out.append('--%s--' % boundary)
    out.append('')

    return boundary, CRLF.join(out)

def parse_multipart(request, boundary, data):
    """
    Parse a ``multipart/form-data`` request body and modify the request's
    ``post`` and ``files`` dictionaries as is appropriate.

    =========  ============
    Argument   Description
    =========  ============
    request    An :class:`HTTPRequest` instance that should be modified to include the parsed data.
    boundary   The ``multipart/form-data`` boundary to be used for splitting the data into parts.
    data       The data to be parsed.
    =========  ============
    """

    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]

    footer_length = len(boundary) + 4
    if data.endswith(CRLF):
        footer_length += 2

    parts = data[:-footer_length].split('--%s%s' % (boundary, CRLF))
    for part in parts:
        if not part:
            continue

        eoh = part.find(DOUBLE_CRLF)
        if eoh == -1:
            log.warning(
                'Missing part headers in multipart/form-data. Skipping.')
            continue

        headers = read_headers(part[:eoh])
        name_header = headers.get('Content-Disposition', '')
        if not name_header.startswith('form-data;') or not part.endswith(CRLF):
            log.warning('Invalid multipart/form-data part.')
            continue

        value = part[eoh+4:-2]
        name_values = {}
        for name_part in name_header[10:].split(';'):
            name, name_value = name_part.strip().split('=', 1)
            name_values[name] = name_value.strip('"').decode('utf-8')

        if not 'name' in name_values:
            log.warning('Missing name value in multipart/form-data part.')
            continue

        name = name_values['name']
        if 'filename' in name_values:
            content_type = headers.get('Content-Type', 'application/unknown')
            request.files.setdefault(name, []).append(dict(
                filename=name_values['filename'], body=value,
                content_type=content_type))
        else:
            request.post.setdefault(name, []).append(value)

def read_headers(data, target=None):
    """
    Read HTTP headers from the supplied data string and return a dictionary
    of those headers. If bad data is supplied, a :class:`BadRequest` exception
    will be raised.

    =========  ============
    Argument   Description
    =========  ============
    data       A data string containing HTTP headers.
    target     *Optional.* A dictionary in which to place the processed headers.
    =========  ============
    """
    if target is None:
        target = {}

    data = data.rstrip(CRLF)
    key = None

    for line in data.splitlines():
        if not line:
            raise BadRequest('Illegal header line: %r' % line)
        if line[0] in ' \t':
            val = line.strip()
        else:
            try:
                key, sep, val = line.partition(':')
            except ValueError:
                raise BadRequest('Illegal header line: %r' % line)

            key = key.rstrip()
            val = val.strip()

        if key in target:
            if key in COMMA_HEADERS:
                target[key] = '%s, %s' % (target[key], val)
            elif isinstance(target[key], list):
                target[key].append(val)
            else:
                target[key] = [target[key], val]
            continue
        target[key] = val

    return target

def date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
