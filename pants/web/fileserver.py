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

import mimetypes
import time

from pants.web.application import abort, Application, redirect
from pants.web.utils import *

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
    def __init__(self, path, blacklist=(re.compile('.*\.py[co]?$'), ),
            defaults=('index.html', 'index.htm'),
            renderers=None):
        # Make sure our path is unicode.
        if not isinstance(path, unicode):
            path = decode(path)

        self.path = os.path.normpath(os.path.realpath(path))
        self.defaults = defaults
        self.renderers = renderers or {}

        # Build the blacklist.
        self.blacklist = []
        for bl in blacklist:
            if isinstance(bl, str):
                bl = re.compile(bl)
            self.blacklist.append(bl)

    def attach(self, app, path='/static/'):
        """
        Attach this fileserver to an application, bypassing the usual route
        decorator to ensure things are done right.

        =========  ===============  ============
        Argument   Default          Description
        =========  ===============  ============
        app                         The :class:`~pants.contrib.web.Application` instance to attach to.
        rule       ``'/static/'``   *Optional.* The path to serve requests from.
        =========  ===============  ============
        """
        if not path.endswith("/"):
            path += '/'
        app.basic_route(path + '<regex("(.*)"):path>', func=self)

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
            if path is None:
                path = request.path
        except (AttributeError, IndexError):
            path = request.path

        # Convert the path to unicode.
        path = decode(urllib.unquote(path))

        # Strip off a starting quote.
        if path.startswith('/') or path.startswith('\\'):
            path = path[1:]

        # Normalize the path.
        full_path = os.path.normpath(os.path.join(self.path, path))

        # Validate the request.
        if not full_path.startswith(self.path):
            abort(403)
        if not os.path.exists(full_path):
            abort()

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

        request.connection.write_file(f, nbytes=length, offset=range[0])
        request.connection._finished = True

    def list_directory(self, request, path):
        """
        Generate a directory listing and return it.
        """

        # Normalize the path.
        full_path = os.path.normpath(os.path.join(self.path, path))

        # Get the URI, which is just request.path decoded.
        uri = decode(urllib.unquote(request.path))
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
                u'%Y-%m-%d %I:%M:%S %p'
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

            obj.append(DIRECTORY_ENTRY.safe_substitute(
                        cls=cls,
                        uri=uri + link,
                        name=p,
                        size=size,
                        modified=mtime
                        ))

        if files or dirs:
            files = u''.join(dirs) + u''.join(files)
        else:
            files = (u'<tr><td colspan="3" class="noborder">'
                     u'<div class="footer center">'
                     u'This directory is empty.</div></td></tr>')

        if Application.current_app and Application.current_app.debug:
            rtime = u'%0.3f ms' % (1000 * request.time)
        else:
            rtime = u''

        output = DIRECTORY_PAGE.safe_substitute(
                    path=uri,
                    go_up=go_up,
                    host=request.host,
                    schema=request.protocol,
                    content=''.join(files),
                    debug=rtime
                    )

        return output, 200, {'Content-Type': 'text/html; charset=UTF-8'}

###############################################################################
# Private Helper Functions
###############################################################################

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
    if not size:
        return u'0 B'

    for f,s in _abbreviations:
        if size >= f:
            break

    ip, dp = str(size/float(f)).split('.')
    if int(dp[:precision]):
        return  u'%s.%s%s' % (ip,dp[:precision],s)
    return u'%s%s' % (ip,s)

def _parse_date(text):
    for fmt in DATE_FORMATS:
        try:
            return datetime(*time.strptime(text, fmt)[:6])
        except ValueError:
            continue
    raise ValueError("Unable to parse time data %r." % text)
