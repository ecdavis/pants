###############################################################################
#
# Copyright 2009 Facebook (see CREDITS.txt)
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
"""
Implementation of a non-blocking, socket-wrapping channel.
"""

###############################################################################
# Imports
###############################################################################

import errno
import os
import socket

from pants.engine import Engine
from pants.util.sendfile import sendfile


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Constants
###############################################################################

#: The socket families supported by Pants.
try:
    SUPPORTED_FAMILIES = (socket.AF_INET, socket.AF_UNIX)
except AttributeError:
    # Silly Windows.
    SUPPORTED_FAMILIES = (socket.AF_INET, )

#: The socket types supported by Pants.
SUPPORTED_TYPES = (socket.SOCK_STREAM, socket.SOCK_DGRAM)


###############################################################################
# Functions
###############################################################################

def strerror(err):
    """
    Given an error number, returns the appropriate error message.
    """
    errstr = "Unknown error %d." % err
    try:
        errstr = os.strerror(err)
    except (NameError, OverflowError, ValueError):
        if err in errno.errorcode:
            errstr = errno.errorcode[err]

    return errstr


###############################################################################
# _Channel Class
###############################################################################

class _Channel(object):
    """
    A simple socket wrapper class.

    _Channel wraps most common socket methods to make them "safe" and
    somewhat more consistent in their return values. This class is
    intended to be subclasses and doesn't really provide a public API.
    Subclasses should override
    :meth:`~pants._channel._Channel._handle_read_event` and
    :meth:`~pants._channel._Channel._handle_write_event` to implement
    basic event-handling behaviour. Subclasses should also ensure that
    they call the various on_* event handler placeholders at the
    appropriate times.

    ==================  ============
    Keyword Arguments   Description
    ==================  ============
    family              *Optional.* A supported socket family. By default, is :const:`socket.AF_INET`.
    type                *Optional.* A supported socket type. By default, is :const:`socket.SOCK_STREAM`.
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
    """
    def __init__(self, **kwargs):
        # Keyword arguments
        sock_family = kwargs.get("family", socket.AF_INET)
        sock_type = kwargs.get("type", socket.SOCK_STREAM)
        sock = kwargs.get("socket", None)
        if sock is None:
            sock = socket.socket(sock_family, sock_type)

        # Socket
        self.fileno = None
        self._socket = None
        self._socket_set(sock)

        # Socket state
        self._wait_for_read_event = True
        self._wait_for_write_event = True

        # I/O attributes
        self._recv_amount = 4096

        # Events
        self._events = Engine.ALL_EVENTS
        Engine.instance().add_channel(self)

    ##### Control Methods #####################################################

    def close(self):
        """
        Close the channel.
        """
        if self._socket is None:
            return

        Engine.instance().remove_channel(self)
        self._socket_close()
        self._safely_call(self.on_close)

    ##### Public Event Handlers ###############################################

    def on_read(self, data):
        """
        Placeholder. Called when data is read from the channel.

        =========  ============
        Argument   Description
        =========  ============
        data       A chunk of data received from the socket.
        =========  ============
        """
        pass

    def on_write(self):
        """
        Placeholder. Called after the channel has finished writing data.
        """
        pass

    def on_connect(self):
        """
        Placeholder. Called after the channel has connected to a remote
        socket.
        """
        pass

    def on_connect_error(self, err, errstr):
        """
        Placeholder. Called when the channel has failed to connect to a
        remote socket.

        =========  ============
        Argument   Description
        =========  ============
        err        The error number that was raised.
        errstr     The error message.
        =========  ============
        """
        pass

    def on_listen(self):
        """
        Placeholder. Called when the channel begins listening for new
        connections or packets.
        """
        pass

    def on_accept(self, sock, addr):
        """
        Placeholder. Called after the channel has accepted a new
        connection.

        =========  ============
        Argument   Description
        =========  ============
        sock       The newly connected socket object.
        addr       The new socket's address.
        =========  ============
        """
        pass

    def on_close(self):
        """
        Placeholder. Called after the channel has finished closing.
        """
        pass

    ##### Socket Method Wrappers ##############################################

    def _socket_set(self, sock):
        """
        Set the channel's current socket and update channel details.

        =========  ============
        Argument   Description
        =========  ============
        sock       A socket for this channel to wrap.
        =========  ============
        """
        if self._socket is not None:
            raise RuntimeError("Cannot replace existing socket.")
        if sock.family not in SUPPORTED_FAMILIES:
            raise ValueError("Unsupported socket family.")
        if sock.type not in SUPPORTED_TYPES:
            raise ValueError("Unsupported socket type.")

        sock.setblocking(False)
        self.fileno = sock.fileno()
        self._socket = sock

    def _socket_connect(self, addr):
        """
        Connect the socket to a remote socket at the given address.

        Returns True if the connection was immediate, False otherwise.

        =========  ============
        Argument   Description
        =========  ============
        addr       The remote address to connect to.
        =========  ============
        """
        try:
            result = self._socket.connect_ex(addr)
        except socket.error, err:
            result = err[0]

        if not result or result == errno.EISCONN:
            return True

        if result in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS, errno.EALREADY):
            self._wait_for_write_event = True
            return False

        raise socket.error(result, strerror(result))

    def _socket_bind(self, addr):
        """
        Bind the socket to the given address.

        =========  ============
        Argument   Description
        =========  ============
        addr       The local address to bind to.
        =========  ============
        """
        self._socket.bind(addr)

    def _socket_listen(self, backlog):
        """
        Begin listening for connections made to the socket.

        =========  ============
        Argument   Description
        =========  ============
        backlog    The size of the connection queue.
        =========  ============
        """
        if os.name == "nt" and backlog > 5:
            log.warning("Setting backlog to SOMAXCONN due to OS constraints.")
            backlog = socket.SOMAXCONN

        self._socket.listen(backlog)
        self._wait_for_read_event = True

    def _socket_close(self):
        """
        Close the socket.
        """
        try:
            self._socket.close()
        except (AttributeError, socket.error):
            return
        finally:
            self.fileno = None
            self._socket = None

    def _socket_accept(self):
        """
        Accept a new connection to the socket.

        Returns a 2-tuple containing the new socket and its remote
        address. The 2-tuple is (None, None) if no connection was
        accepted.
        """
        try:
            return self._socket.accept()
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._wait_for_read_event = True
                return None, None
            else:
                raise

    def _socket_recv(self):
        """
        Receive data from the socket.

        Returns a string of data read from the socket. The data is None if
        the socket has been closed.
        """
        try:
            data = self._socket.recv(self._recv_amount)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._wait_for_read_event = True
                return ''
            elif err[0] == errno.ECONNRESET:
                return None
            else:
                raise

        if not data:
            return None
        else:
            return data

    def _socket_recvfrom(self):
        """
        Receive data from the socket.

        Returns a 2-tuple containing a string of data read from the socket
        and the address of the sender. The data is None if reading failed.
        The data and address are None if no data was received.
        """
        try:
            data, addr = self._socket.recvfrom(self._recv_amount)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ECONNRESET):
                self._wait_for_read_event = True
                return '', None
            else:
                raise

        if not data:
            return None, None
        else:
            return data, addr

    def _socket_send(self, data):
        """
        Send data to the socket.

        Returns the number of bytes that were sent to the socket.

        =========  ============
        Argument   Description
        =========  ============
        data       The string of data to send.
        =========  ============
        """
        try:
            return self._socket.send(data)
        except Exception, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._wait_for_write_event = True
                return 0
            elif err[0] == errno.EPIPE:
                self.close()
                return 0
            else:
                raise

    def _socket_sendto(self, data, addr, flags=0):
        """
        Send data to a remote socket.

        Returns the number of bytes that were sent to the socket.

        =========  ============
        Argument   Description
        =========  ============
        data       The string of data to send.
        addr       The remote address to send to.
        flags      *Optional.* Flags to pass to the sendto call.
        =========  ============
        """
        try:
            return self._socket.sendto(data, flags, addr)
        except Exception, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._wait_for_write_event = True
                return 0
            elif err[0] == errno.EPIPE:
                self.close()
                return 0
            else:
                raise

    def _socket_sendfile(self, sfile, offset, nbytes):
        """
        =========  ============
        Argument   Description
        =========  ============
        sfile      The file to send.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
        =========  ============
        """
        try:
            return sendfile(sfile, self, offset, nbytes)
        except Exception, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._wait_for_write_event = True
                return 0
            elif err[0] == errno.EPIPE:
                self.close()
                return 0
            else:
                raise

    ##### Internal Methods ####################################################

    def _safely_call(self, thing_to_call, *args, **kwargs):
        """
        Safely execute a callable.

        The callable is wrapped in a try block and executed. If an
        exception is raised it is logged.

        ==============  ============
        Argument        Description
        ==============  ============
        thing_to_call   The callable to execute.
        *args           The positional arguments to be passed to the callable.
        **kwargs        The keyword arguments to be passed to the callable.
        ==============  ============
        """
        try:
            return thing_to_call(*args, **kwargs)
        except Exception:
            log.exception("Exception raised on %s #%d." %
                    (self.__class__.__name__, self.fileno or -1))

    def _get_socket_error(self):
        """
        Get the most recent error that occured on the socket.

        Returns a 2-tuple containing the error code and the error message.
        """
        err = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        errstr = ""

        if err != 0:
            errstr = strerror(err)

        return err, errstr

    ##### Internal Event Handler Methods ######################################

    def _handle_events(self, events):
        """
        Handle events raised on the channel.

        =========  ============
        Argument   Description
        =========  ============
        events     The events in the form of an integer.
        =========  ============
        """
        if self._socket is None:
            log.warning("Received events for closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        if events & Engine.READ:
            self._wait_for_read_event = False
            self._handle_read_event()
            if self._socket is None:
                return

        if events & Engine.WRITE:
            self._wait_for_write_event = False
            self._handle_write_event()
            if self._socket is None:
                return

        if events & Engine.ERROR:
            err, errstr = self._get_socket_error()
            if err != 0:
                log.error("Error on %s #%d: %s (%d)" %
                        (self.__class__.__name__, self.fileno, errstr, err))
            self.close()
            return

        if events & Engine.HANGUP:
            log.debug("Hang up on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            self.close()
            return

        events = Engine.ERROR | Engine.HANGUP
        if self._wait_for_read_event:
            events |= Engine.READ
        if self._wait_for_write_event:
            events |= Engine.WRITE
        if events != self._events:
            self._events = events
            Engine.instance().modify_channel(self)

    def _handle_read_event(self):
        """
        Handle a read event raised on the channel.

        Not implemented in :class:`~pants._channel._Channel`.
        """
        raise NotImplementedError

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.

        Not implemented in :class:`~pants._channel._Channel`.
        """
        raise NotImplementedError
