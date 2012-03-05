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
Various implementations of the platform-dependant sendfile() system
call.
"""

###############################################################################
# Imports
###############################################################################

import os
import socket
import sys

import ctypes
import ctypes.util


###############################################################################
# Constants
###############################################################################

SENDFILE_PLATFORMS = ("linux2", "darwin", "freebsd", "dragonfly")
SENDFILE_AMOUNT = 2 ** 16


###############################################################################
# Implementations
###############################################################################

def sendfile_fallback(sfile, channel, offset, nbytes, fallback):
    """
    Fallback implementation of ``sendfile()``.

    This is not a true implementation of the ``sendfile()`` system call,
    but rather a fallback option written in Python. It has the same
    ultimate effect, but is far slower than a native implementation.
    This function is only used as a last resort.

    =========  ============
    Argument   Description
    =========  ============
    sfile      The file to send.
    channel    The channel to write to.
    offset     The number of bytes to offset writing by.
    nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
    fallback   If True, the pure-Python sendfile function will be used.
    =========  ============
    """
    # TODO Implement a better solution for the "send all bytes" argument.
    if nbytes == 0:
        to_read = SENDFILE_AMOUNT
    else:
        to_read = min(nbytes, SENDFILE_AMOUNT)

    sfile.seek(offset)
    data = sfile.read(to_read)

    if len(data) == 0:
        return 0

    return channel._socket_send(data)

def sendfile_linux(sfile, channel, offset, nbytes, fallback):
    """
    Linux 2.x implementation of ``sendfile()``.

    =========  ============
    Argument   Description
    =========  ============
    sfile      The file to send.
    channel    The channel to write to.
    offset     The number of bytes to offset writing by.
    nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
    fallback   If True, the pure-Python sendfile function will be used.
    =========  ============
    """
    if fallback:
        return sendfile_fallback(sfile, channel, offset, nbytes, fallback)

    # TODO Linux doesn't support an argument of 0 for nbytes. Implement
    #      a better solution.
    if nbytes == 0:
        nbytes = SENDFILE_AMOUNT

    _offset = ctypes.c_uint64(offset)

    result = _sendfile(channel.fileno, sfile.fileno(), _offset, nbytes)

    if result == -1:
        e = ctypes.get_errno()
        raise socket.error(e, os.strerror(e))

    return result

def sendfile_darwin(sfile, channel, offset, nbytes, fallback):
    """
    Darwin implementation of ``sendfile()``.

    =========  ============
    Argument   Description
    =========  ============
    sfile      The file to send.
    channel    The channel to write to.
    offset     The number of bytes to offset writing by.
    nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
    fallback   If True, the pure-Python sendfile function will be used.
    =========  ============
    """
    if fallback:
        return sendfile_fallback(sfile, channel, offset, nbytes, fallback)

    _nbytes = ctypes.c_uint64(nbytes)

    result = _sendfile(sfile.fileno(), channel.fileno, offset, _nbytes,
                       None, 0)

    if result == -1:
        e = ctypes.get_errno()
        raise socket.error(e, os.strerror(e))

    return _nbytes.value

def sendfile_bsd(sfile, channel, offset, nbytes, fallback):
    """
    FreeBSD/Dragonfly implementation of ``sendfile()``.

    =========  ============
    Argument   Description
    =========  ============
    sfile      The file to send.
    channel    The channel to write to.
    offset     The number of bytes to offset writing by.
    nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
    fallback   If True, the pure-Python sendfile function will be used.
    =========  ============
    """
    if fallback:
        return sendfile_fallback(sfile, channel, offset, nbytes, fallback)

    _nbytes = ctypes.c_uint64()

    result = _sendfile(sfile.fileno(), channel.fileno, offset, nbytes,
                       None, _nbytes, 0)

    if result == -1:
        e = ctypes.get_errno()
        raise socket.error(e, os.strerror(e))

    return _nbytes.value


###############################################################################
# Sendfile
###############################################################################

_sendfile = None
if sys.version_info >= (2, 6) and sys.platform in SENDFILE_PLATFORMS:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if hasattr(_libc, "sendfile"):
        _sendfile = _libc.sendfile

sendfile = None
if _sendfile is None:
    sendfile = sendfile_fallback

elif sys.platform == "linux2":
    _sendfile.argtypes = (
            ctypes.c_int,  # socket
            ctypes.c_int,  # file
            ctypes.POINTER(ctypes.c_uint64), #  offset
            ctypes.c_size_t  # len
            )

    sendfile = sendfile_linux

elif sys.platform == "darwin":
    _sendfile.argtypes = (
            ctypes.c_int,  # file
            ctypes.c_int,  # socket
            ctypes.c_uint64, # offset
            ctypes.POINTER(ctypes.c_uint64),  # len
            ctypes.c_voidp,  # header/trailer
            ctypes.c_int  # flags
            )

    sendfile = sendfile_darwin

elif sys.platform in ("freebsd", "dragonfly"):
    _sendfile.argtypes = (
            ctypes.c_int,  # file
            ctypes.c_int,  # socket
            ctypes.c_uint64,  # offset
            ctypes.c_uint64,  # len
            ctypes.c_voidp,  # header/trailer
            ctypes.POINTER(ctypes.c_uint64),  # bytes sent
            ctypes.c_int  # flags
            )

    sendfile = sendfile_bsd
