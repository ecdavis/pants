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

import hashlib
import hmac
import logging
import mimetypes
import re

from itertools import imap

from pants import __version__ as pants_version


###############################################################################
# Logging
###############################################################################

log = logging.getLogger("pants.http")


###############################################################################
# Constants
###############################################################################

WHITESPACE = re.compile(r"\s+")

SERVER      = 'HTTPants (pants/%s)' % pants_version
SERVER_URL  = 'http://www.pantspowered.org/'

USER_AGENT = "HTTPants/%s" % pants_version

COMMA_HEADERS = ('Accept', 'Accept-Charset', 'Accept-Encoding',
    'Accept-Language', 'Accept-Ranges', 'Allow', 'Cache-Control', 'Connection',
    'Content-Encoding', 'Content-Language', 'Expect', 'If-Match',
    'If-None-Match', 'Pragma', 'Proxy-Authenticate', 'TE', 'Trailer',
    'Transfer-Encoding', 'Upgrade', 'Vary', 'Via', 'Warning',
    'WWW-Authenticate')

STRANGE_HEADERS = {
    'a-im': 'A-IM',
    'c-pep': 'C-PEP',
    'c-pep-info': 'C-PEP-Info',
    'content-id': 'Content-ID',
    'content-md5': 'Content-MD5',
    'dasl': 'DASL',
    'dav': 'DAV',
    'dl-expansion-history': 'DL-Expansion-History',
    'differential-id': 'Differential-ID',
    'dnt': 'DNT',
    'ediint-features': 'EDIINT-Features',
    'etag': 'ETag',
    'getprofile': 'GetProfile',
    'im': 'IM',
    'message-id': 'Message-ID',
    'mime-version': 'MIME-Version',
    'p3p': 'P3P',
    'pep': 'PEP',
    'pics-label': 'PICS-Label',
    'profileobject': 'ProfileObject',
    'sec-websocket-accept': 'Sec-WebSocket-Accept',
    'sec-websocket-extensions': 'Sec-WebSocket-Extensions',
    'sec-websocket-key': 'Sec-WebSocket-Key',
    'sec-websocket-protocol': 'Sec-WebSocket-Protocol',
    'sec-websocket-version': 'Sec-WebSocket-Version',
    'setprofile': 'SetProfile',
    'slug': 'SLUG',
    'soapaction': 'SoapAction',
    'status-uri': 'Status-URI',
    'subok': 'SubOK',
    'tcn': 'TCN',
    'te': 'TE',
    'ua-color': 'UA-Color',
    'ua-media': 'UA-Media',
    'ua-pixels': 'UA-Pixels',
    'ua-resolution': 'UA-Resolution',
    'ua-windowpixels': 'UA-Windowpixels',
    'uri': 'URI',
    'vbr-info': 'VBR-Info',
    'www-authenticate': 'WWW-Authenticate',
    'x400-mts-identifier': 'X400-MTS-Identifier',
    'x-att-deviceid': 'X-ATT-DeviceId',
    'x-ua-compatible': 'X-UA-Compatible',
    'x-xss-protection': 'X-XSS-Protection',
}

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
# Header Case Normalization
###############################################################################

class HeadingNormalizer(dict):
    def __missing__(self, key):
        ret = self[key] = "-".join(x.capitalize() for x in key.split("-"))
        return ret

_normalize_header = HeadingNormalizer(STRANGE_HEADERS).__getitem__

for hdr in ('accept', 'accept-charset', 'accept-encoding', 'accept-language',
            'accept-datetime', 'authorization', 'cache-control', 'connection',
            'cookie', 'content-length', 'content-type', 'date', 'expect',
            'from', 'host', 'if-match', 'if-modified-since', 'if-none-match',
            'if-range', 'if-unmodified-since', 'max-forwards', 'pragma',
            'proxy-authorization', 'range', 'referer', 'upgrade', 'user-agent',
            'via', 'warning', 'x-requested-with', 'x-forwarded-for',
            'x-forwarded-proto', 'front-end-https', 'x-wap-profile',
            'proxy-connection', 'access-control-allow-origin', 'accept-ranges',
            'age', 'allow', 'content-encoding', 'content-language',
            'content-location', 'content-disposition', 'content-range',
            'expires', 'last-modified', 'link', 'location',
            'proxy-authenticate', 'refresh', 'retry-after', 'server',
            'set-cookie', 'strict-transport-security', 'trailer',
            'transfer-encoding', 'vary', 'x-frame-options',
            'x-content-type-options', 'x-powered-by'):
    _normalize_header(hdr)


###############################################################################
# HTTPHeaders Class
###############################################################################

class HTTPHeaders(object):
    """
    HTTPHeaders is a dict-like object that holds parsed HTTP headers, provides
    access to them in a case-insensitive way, and that normalizes the case of
    the headers upon iteration.
    """

    __slots__ = ('_data',)

    def __init__(self, data=None, _store=None):
        self._data = _store or {}
        if data:
            self.update(data)

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, dict(self.iteritems()))

    def __len__(self):
        return len(self._data)

    def __eq__(self, other, _normalize_header=_normalize_header):
        if isinstance(other, HTTPHeaders):
            return self._data == other._data

        for k, v in self._data.iteritems():
            k = _normalize_header(k)
            if not (k in other) or not (other[k] == v):
                return 0
        return len(self._data) == len(other)

    def iteritems(self, _normalize_header=_normalize_header):
        for k, v in self._data.iteritems():
            yield _normalize_header(k), v

    def iterkeys(self):
        return imap(_normalize_header, self._data)

    __iter__ = iterkeys

    def itervalues(self):
        return self._data.itervalues()

    def items(self, _normalize_header=_normalize_header):
        return [(_normalize_header(k), v) for k,v in self._data.iteritems()]

    def keys(self, _normalize_header=_normalize_header):
        return [_normalize_header(k) for k in self._data]

    def values(self):
        return self._data.values()

    def update(self, iterable=None, **kwargs):
        if iterable:
            if hasattr(iterable, 'keys'):
                for k in iterable:
                    self[k] = iterable[k]
            else:
                for (k,v) in iterable:
                    self[k] = v

        for k,v in kwargs.iteritems():
            self[k] = v

    def __setitem__(self, key, value):
        self._data[key.lower()] = value

    def __delitem__(self, key):
        del self._data[key.lower()]

    def __contains__(self, key):
        return key.lower() in self._data

    has_key = __contains__

    def __getitem__(self, key):
        return self._data[key.lower()]

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)

    def setdefault(self, key, default=None):
        return self._data.setdefault(key.lower(), default)

    def clear(self):
        self._data.clear()

    def copy(self):
        return self.__class__(_store=self._data.copy())

    def pop(self, key, *default):
        return self._data.pop(key, *default)

    def popitem(self):
        key, val = self._data.popitem()
        return _normalize_header(key), val


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

                key = key.strip().lower()
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
        target = HTTPHeaders(_store=target)

    return target

def date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
