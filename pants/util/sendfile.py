###############################################################################
#
# Copyright 2011 Pants (see AUTHORS.txt)
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
# Sendfile
###############################################################################

_sendfile = None
if sys.version_info >= (2,6) and sys.platform in SENDFILE_PLATFORMS:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if hasattr(_libc, "sendfile"):
        _sendfile = _libc.sendfile

if _sendfile is None:
    def sendfile(sfile, channel, offset, nbytes):
        """
        Fallback implementation of sendfile().

        =========  ============
        Argument   Description
        =========  ============
        sfile      The file to send.
        channel    The channel to write to.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
        =========  ============
        """
        if nbytes == 0:
            to_read = SENDFILE_AMOUNT
        else:
            to_read = min(nbytes, SENDFILE_AMOUNT)

        sfile.seek(offset)
        data = sfile.read(to_read)

        if len(data) == 0:
            return 0

        return channel._socket_send(data)

elif sys.platform == "linux2":
    _sendfile.argtypes = (
            ctypes.c_int, # socket
            ctypes.c_int, # file
            ctypes.POINTER(ctypes.c_uint64), # offset
            ctypes.c_size_t # len
            )

    def sendfile(sfile, channel, offset, nbytes):
        """
        Linux 2.x implementation of sendfile().

        =========  ============
        Argument   Description
        =========  ============
        sfile      The file to send.
        channel    The channel to write to.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
        =========  ============
        """
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

elif sys.platform == "darwin":
    _sendfile.argtypes = (
            ctypes.c_int, # file
            ctypes.c_int, # socket
            ctypes.c_uint64, # offset
            ctypes.POINTER(ctypes.c_uint64), # len
            ctypes.c_voidp, # header/trailer
            ctypes.c_int # flags
            )

    def sendfile(sfile, channel, offset, nbytes):
        """
        Darwin implementation of sendfile().

        =========  ============
        Argument   Description
        =========  ============
        sfile      The file to send.
        channel    The channel to write to.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
        =========  ============
        """
        _nbytes = ctypes.c_uint64(nbytes)

        result = _sendfile(sfile.fileno(), channel.fileno, offset, _nbytes,
                           None, 0)

        if result == -1:
            e = ctypes.get_errno()
            raise socket.error(e, os.strerror(e))

        return _nbytes.value

elif sys.platform in ("freebsd", "dragonfly"):
    _sendfile.argtypes = (
            ctypes.c_int, # file
            ctypes.c_int, # socket
            ctypes.c_uint64, # offset
            ctypes.c_uint64, # len
            ctypes.c_voidp, # header/trailer
            ctypes.POINTER(ctypes.c_uint64), # bytes sent
            ctypes.c_int # flags
            )

    def sendfile(sfile, channel, offset, nbytes):
        """
        FreeBSD/Dragonfly implementation of sendfile().

        =========  ============
        Argument   Description
        =========  ============
        sfile      The file to send.
        channel    The channel to write to.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
        =========  ============
        """
        _nbytes = ctypes.c_uint64()

        result = _sendfile(sfile.fileno(), channel.fileno, offset, nbytes,
                           None, _nbytes, 0)

        if result == -1:
            e = ctypes.get_errno()
            raise socket.error(e, os.strerror(e))

        return _nbytes.value
