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
import sys
import time

from pants.engine import Engine
from pants.util.sendfile import sendfile

dns = None


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Constants
###############################################################################

SUPPORTED_FAMILIES = [socket.AF_INET]
try:
    SUPPORTED_FAMILIES.append(socket.AF_UNIX)
except AttributeError:
    # Unix sockets not supported.
    pass

if socket.has_ipv6:
    SUPPORTED_FAMILIES.append(socket.AF_INET6)

    if sys.platform == "win32":
        # IPv6 support may not be installed on Windows XP.
        try:
            socket.socket(socket.AF_INET6)
        except socket.error:
            SUPPORTED_FAMILIES.remove(socket.AF_INET6)

SUPPORTED_FAMILIES = tuple(SUPPORTED_FAMILIES)
SUPPORTED_TYPES = (socket.SOCK_STREAM, socket.SOCK_DGRAM)

if sys.platform == "win32":
    FAMILY_ERROR = (10047, "WSAEAFNOSUPPORT")
    NAME_ERROR = (11001, "WSAHOST_NOT_FOUND")
else:
    FAMILY_ERROR = (97, "Address family not supported by protocol")
    NAME_ERROR = (-2, "Name or service not known")


###############################################################################
# Functions
###############################################################################

# os.strerror() is buggy on Windows, so we have to look up the error
# string manually.
if sys.platform == "win32":
    def strerror(err):
        if err in socket.errorTab:
            errstr = socket.errorTab[err]
        elif err in errno.errorcode:
            errstr = socket.errorcode[err]
        else:
            errstr = os.strerror(err)
            if errstr == "Unknown error":
                errstr += ": %d" % err
        return errstr
else:
    strerror = os.strerror


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
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
    """
    def __init__(self, **kwargs):
        # Keyword arguments
        sock = kwargs.get("socket", None)

        # Socket
        self.family = None
        self.fileno = None
        self._socket = None
        self._closed = False
        if sock:
            self._socket_set(sock)

        # I/O attributes
        self._recv_amount = 4096

        # Internal state
        self._events = Engine.ALL_EVENTS
        self._processing_events = False
        if self._socket:
            Engine.instance().add_channel(self)

    def __repr__(self):
        return "%s #%r (%s)" % (self.__class__.__name__, self.fileno,
                object.__repr__(self))

    ##### Control Methods #####################################################

    def close(self):
        """
        Close the channel.
        """
        if self._closed:
            return

        Engine.instance().remove_channel(self)
        self._socket_close()
        self._events = Engine.ALL_EVENTS
        self._processing_events = False

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

    def on_connect_error(self, exception):
        """
        Placeholder. Called when the channel has failed to connect to a
        remote socket.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        pass

    def on_overflow_error(self, exception):
        """
        Placeholder. Called when an internal buffer on the channel
        exceeds its size limit.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close()

    def on_error(self, exception):
        """
        Placeholder. Generic error handler for exceptions raised on the
        channel. Called when no specific handler exists.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close()

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
        self.family = sock.family
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
            self._start_waiting_for_write_event()
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
        if sys.platform == "win32" and backlog > 5:
            log.warning("Setting backlog to SOMAXCONN due to OS constraints.")
            backlog = socket.SOMAXCONN

        self._socket.listen(backlog)

    def _socket_close(self):
        """
        Close the socket.
        """
        try:
            self._socket.close()
        except (AttributeError, socket.error):
            return
        finally:
            self.family = None
            self.fileno = None
            self._socket = None
            self._closed = True

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
                self._start_waiting_for_write_event()
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
                self._start_waiting_for_write_event()
                return 0
            elif err[0] == errno.EPIPE:
                self.close()
                return 0
            else:
                raise

    def _socket_sendfile(self, sfile, offset, nbytes):
        """
        Send data from a file to a remote socket.

        Returns the number of bytes that were sent to the socket.

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
                self._start_waiting_for_write_event()
                return 0
            elif err[0] == errno.EPIPE:
                self.close()
                return 0
            else:
                raise

    ##### Internal Methods ####################################################

    def _start_waiting_for_write_event(self):
        """
        Start waiting for a write event on the channel, and update the
        engine accordingly.
        """
        if self._events != self._events | Engine.WRITE:
            self._events = self._events | Engine.WRITE
            if not self._processing_events:
                Engine.instance().modify_channel(self)

    def _stop_waiting_for_write_event(self):
        """
        Stop waiting for a write event on the channel, and update the
        engine accordingly.
        """
        if self._events == self._events | Engine.WRITE:
            self._events = self._events & (self._events ^ Engine.WRITE)
            if not self._processing_events:
                Engine.instance().modify_channel(self)

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
            log.exception("Exception raised in callback on %r." % self)

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

    def _resolve_addr(self, addr, native_resolve, callback):
        """
        Resolve the given address into something that can be connected to
        immediately.
        """
        global dns
        if dns is None:
            from pants.util import dns

        if isinstance(addr, str):
            # This is a unix socket!
            if not hasattr(socket, "AF_UNIX"):
                callback(None, None, FAMILY_ERROR)
                return
            callback(addr, socket.AF_UNIX)
            return

        # Check for a port only.
        if isinstance(addr, int):
            # INADDR_ANY-atize it!
            addr = ('', addr)

        # Check for INADDR_ANY or INADDR_BROADCAST.
        if addr[0] in ('', '<broadcast>'):
            if socket.has_ipv6:
                callback(addr, socket.AF_INET6)
            elif len(addr) == 4:
                callback(None, None, FAMILY_ERROR)
            else:
                callback(addr, socket.AF_INET)
            return

        # It must be a tuple or list. Or, at least, assume it is.
        # That means it's either an AF_INET or AF_INET6 address.
        got_family = None

        if socket.has_ipv6:
            try:
                result = socket.inet_pton(socket.AF_INET6, addr[0])
                got_family = socket.AF_INET6
            except socket.error:
                pass

        if got_family is None and len(addr) == 2:
            try:
                result = socket.inet_pton(socket.AF_INET, addr[0])
                got_family = socket.AF_INET
            except socket.error:
                pass

        # Do it this way so any errors aren't gobbled up in those try thingies.
        if got_family is not None:
            callback(addr, got_family)
            return

        # Do we have to do it natively?
        if native_resolve:
            if len(addr) == 2:
                fam = socket.AF_INET
            else:
                if not socket.has_ipv6:
                    callback(None, None, FAMILY_ERROR)
                    return

                fam = socket.AF_INET6

            try:
                info = socket.getaddrinfo(addr[0], addr[1], fam)[0]
            except socket.gaierror, ex:
                callback(None, None, (ex.errno, ex.strerror))
                return

            callback(info[4], info[0])
            return

        # Guess we have to resolve it with Pants.
        def dns_callback(status, cname, ttl, rdata):
            if status == dns.DNS_NAMEERROR:
                callback(None, None, NAME_ERROR)
                return

            if status != dns.DNS_OK or not rdata:
                self._resolve_addr(addr, True, callback)
                return

            for i in rdata:
                if ':' in i:
                    if not socket.has_ipv6:
                        continue
                    callback((i,) + addr[1:], socket.AF_INET6)
                    return
                else:
                    callback((i,) + addr[1:], socket.AF_INET)
                    return
            else:
                callback(None, None, FAMILY_ERROR)

        if len(addr) == 4:
            if not socket.has_ipv6:
                callback(None, None, FAMILY_ERROR)
                return
            qtype = dns.AAAA
        else:
            qtype = (dns.AAAA, dns.A)

        dns.query(addr[0], qtype, callback=dns_callback)

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
        if self._closed:
            log.warning("Received events for closed %r." % self)
            return

        self._processing_events = True

        previous_events = self._events
        if self._events != Engine.BASE_EVENTS:
            self._events = Engine.BASE_EVENTS

        if events & Engine.READ:
            self._handle_read_event()
            if self._closed:
                return

        if events & Engine.WRITE:
            self._handle_write_event()
            if self._closed:
                return

        if events & Engine.ERROR:
            err, errstr = self._get_socket_error()
            if err != 0:
                log.error("Error on %r: %s (%d)" % (self, errstr, err))
            self.close()
            return

        if events & Engine.HANGUP:
            log.debug("Hang up on %r." % self)
            self.close()
            return

        if self._events != previous_events:
            Engine.instance().modify_channel(self)

        self._processing_events = False

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
