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
``pants.web.fileserver`` implements a basic static file server for use with a
:class:`~pants.http.server.HTTPServer` or
:class:`~pants.web.application.Application`. It makes use of the appropriate
HTTP headers and the ``sendfile`` system call, as well as the ``X-Sendfile``
header to improve transfer performance.

Serving Static Files
====================

The ``pants.web.fileserver`` module can be invoked directly using the *-m*
switch of the interpreter to serve files in a similar way to the standard
library's :mod:`SimpleHTTPServer`. However, it performs much more efficiently
than ``SimpleHTTPServer`` for this task.

.. code-block:: bash

    $ python -m pants.web.fileserver

When doing this, you may use additional arguments to specify which address the
server should bind to, as well as which filenames should serve as directory
indices. By default, only ``index.html`` and ``index.htm`` are served
as indices.

"""

###############################################################################
# Imports
###############################################################################

import mimetypes
import os
import re
import sys
import time
import urllib

from datetime import datetime, timedelta

from pants.http.utils import date, SERVER

from pants.web.application import abort, Application, redirect
from pants.web.utils import DATE_FORMATS, decode, DIRECTORY_ENTRY, \
    DIRECTORY_PAGE, HTTPException


__all__ = (
    "FileServer",  # Core Classes
)

###############################################################################
# Cross Platform Hidden File Detection
###############################################################################

def _is_hidden(file, path):
    return file.startswith(u'.')

if os.name == 'nt':
    try:
        import win32api, win32con
    except ImportError:
        win32api = None
        win32con = None

    if win32api:
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


###############################################################################
# FileServer Class
###############################################################################

class FileServer(object):
    """
    The FileServer is a request handling class that, as it sounds, serves files
    to the client using :meth:`pants.http.server.HTTPRequest.send_file`. As
    such, it supports caching headers, as well as ``X-Sendfile`` if the
    :class:`~pants.http.server.HTTPServer` instance is configured to use the
    Sendfile header. FileServer is also able to take advantage of the
    ``sendfile`` system call to improve performance when ``X-Sendfile`` is not
    in use.

    ==========  ==============================  ============
    Argument    Default                         Description
    ==========  ==============================  ============
    path                                        The path to serve.
    blacklist   ``.py`` and ``.pyc`` files      *Optional.* A list of regular expressions to test filenames against. If a given file matches any of the provided patterns, it will not be downloadable and instead return a ``403 Unauthorized`` error.
    default     ``index.html``, ``index.htm``   *Optional.* A list of default files to be displayed rather than a directory listing if they exist.
    ==========  ==============================  ============

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
            defaults=('index.html', 'index.htm')):
        # Make sure our path is unicode.
        if not isinstance(path, unicode):
            path = decode(path)

        self.path = os.path.normpath(os.path.realpath(path))
        self.defaults = defaults

        # Build the blacklist.
        self.blacklist = []
        for bl in blacklist:
            if isinstance(bl, str):
                bl = re.compile(bl)
            self.blacklist.append(bl)

    def attach(self, app, path='/static/'):
        """
        Attach this FileServer to an :class:`~pants.web.application.Application`,
        bypassing the usual route decorator to ensure the rule is configured as
        FileServer expects.

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
            path = request.match.groups()[-1]
            if path is None:
                path = urllib.unquote_plus(request.path)
        except (AttributeError, IndexError):
            path = urllib.unquote_plus(request.path)

        # Convert the path to unicode.
        path = decode(path)

        # Strip off a starting quote.
        if path.startswith('/') or path.startswith('\\'):
            path = path[1:]

        # Normalize the path.
        full_path = os.path.normpath(os.path.join(self.path, path))

        # Validate the request.
        if not full_path.startswith(self.path):
            abort(403)
        elif not os.path.exists(full_path):
            abort()
        elif not os.access(full_path, os.R_OK):
            abort(403)

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

        # Let's send the file.
        request.auto_finish = False
        request.send_file(full_path)


    def list_directory(self, request, path):
        """
        Generate a directory listing and return it.
        """

        # Normalize the path.
        full_path = os.path.normpath(os.path.join(self.path, path))

        # Get the URL, which is just request.path decoded.
        url = decode(urllib.unquote(request.path))
        if not url.startswith(u'/'):
            url = u'/%s' % url
        if not url.endswith(u'/'):
            return redirect(u'%s/' % url)

        go_up = u''
        if url.strip(u'/'):
            go_up = u'<p><a href="..">Up to Higher Directory</a></p>'

        files = []
        dirs = []

        try:
            contents = os.listdir(full_path)
        except OSError:
            abort(403)

        for p in sorted(contents, key=unicode.lower):
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
                        url=url + link,
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
                    path=url,
                    go_up=go_up,
                    host=request.host,
                    scheme=request.scheme,
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
        return  u'%s.%s%s' % (ip, dp[:precision], s)
    return u'%s%s' % (ip, s)


###############################################################################
# Run as Module Support
###############################################################################

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser(usage="%prog [options] [path]")

    parser.add_option("-b", "--bind", metavar="ADDRESS", dest="address",
        default="8000", help="Bind the server to PORT, INTERFACE:PORT, or unix:PATH")
    parser.add_option("-i", "--index", metavar="FILE", dest="indices",
        action="append", default=[], help="Serve files named FILE if available rather than a directory listing.")

    options, args = parser.parse_args()
    args = ''.join(args)

    # First, get the directory.
    path = os.path.realpath(args)
    if not os.path.exists(path) or not os.path.isdir(path):
        print "The provided path %r is not a directory or does not exist." % path
        sys.exit(1)

    # Parse the address.
    if ':' in options.address:
        address = options.address.split(":", 1)
        if address[0].lower() == "unix":
            address = address[1]
        else:
            address[1] = int(address[1])
    else:
        address = int(options.address)

    # Fix up the indices list.
    indices = options.indices
    if not indices:
        indices.extend(['index.html', 'index.htm'])

    # Create the server now.
    app = Application()
    FileServer(path, [], indices).attach(app, '/')
    print "Serving HTTP with Pants on: %s" % repr(address)

    try:
        app.run(address)
    except (KeyboardInterrupt, SystemExit):
        pass
