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
import hashlib
import hmac
import logging
import mimetypes
import os
import re

from datetime import datetime

if os.name == 'nt':
    from time import clock as time
else:
    from time import time

from pants import Stream, Server
from pants import __version__ as pants_version
from pants.engine import Engine

###############################################################################
# Logging
###############################################################################

log = logging.getLogger("pants.http")

###############################################################################
# Constants
###############################################################################

WHITESPACE = re.compile(r"\s+")

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
    203: 'Non-Authoritative Information',
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
    426: "Upgrade Required",
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
# Case-Insensitive Dict
###############################################################################

class CaseInsensitiveDict(dict):
    """
    A case-insensitive dictionary for storing HTTP headers.
    """

    _caseless_keys = None

    @property
    def caseless_keys(self):
        if not self._caseless_keys:
            self._caseless_keys = dict((x.lower() if isinstance(x, basestring) else x, x) for x in self.keys())
        return self._caseless_keys

    def __setitem__(self, key, value):
        key = self.caseless_keys.get(key.lower(), key)
        dict.__setitem__(self, key, value)
        self._caseless_keys[key.lower()] = key

    def __delitem__(self, key):
        key = self.caseless_keys.get(key.lower(), key)
        dict.__delitem__(self, key)
        self._caseless_keys = None

    def __contains__(self, key):
        return key.lower() in self.caseless_keys

    def get(self, key, default=None):
        key = key.lower()
        if key in self.caseless_keys:
            return dict.__getitem__(self, self._caseless_keys[key])
        return default

    __getitem__ = get

###############################################################################
# Support Functions
###############################################################################

def get_filename(file):
    name = getattr(file, 'name', None)
    if name and not (name.endswith('>') and name.startswith('<')):
        return name

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
    request body, and returns a list of strings and files that can be sent to
    the server, along with the used boundary.

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
        out.append('--%s%sContent-Disposition: form-data; name="%s"%s%s%s' % (boundary, CRLF, k, DOUBLE_CRLF, v, CRLF))
    if files:
        for k, v in files.iteritems():
            if isinstance(v, (list,tuple)):
                fn, v = v
            else:
                fn = get_filename(v)
                if not fn:
                    fn = k

            out.append('--%s%sContent-Disposition: form-data; name="%s"; filename="%s"%sContent-Type: %s%sContent-Transfer-Encoding: binary%s' % (boundary, CRLF, k, fn, CRLF, content_type(fn), CRLF, DOUBLE_CRLF))
            out.append(v)
            out.append(CRLF)

    out.append('--%s--%s' % (boundary, CRLF))

    return boundary, out

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
        cast = True
        target = {}
    else:
        cast = False

    data = data.rstrip(CRLF)
    key = None

    if data:
        for line in data.split(CRLF):
            if not line:
                raise BadRequest('Illegal header line: %r' % line)
            if key and line[0] in ' \t':
                val = line.strip()
                mline = True
            else:
                mline = False
                try:
                    key, val = line.split(':', 1)
                except ValueError:
                    raise BadRequest('Illegal header line: %r' % line)

                key = key.strip()
                val = val.strip()

                try:
                    val = int(val)
                except ValueError:
                    pass

            if key in target:
                if mline:
                    if isinstance(target[key], list):
                        if target[key]:
                            target[key][-1] += ' ' + val
                        else:
                            target[key].append(val)
                    else:
                        target[key] += ' ' + val
                elif key in COMMA_HEADERS:
                    target[key] = '%s, %s' % (target[key], val)
                elif isinstance(target[key], list):
                    target[key].append(val)
                else:
                    target[key] = [target[key], val]
                continue
            target[key] = val

    if cast:
        target = CaseInsensitiveDict(target)

    return target

def date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
