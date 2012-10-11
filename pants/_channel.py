###############################################################################
#
# Copyright 2009 Facebook (see NOTICE.txt)
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
The low-level channel class. Provides a non-blocking socket wrapper for
use as a base for higher-level classes. Intended for internal use only.
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
HAS_UNIX = False
try:
    SUPPORTED_FAMILIES.append(socket.AF_UNIX)
except AttributeError:
    # Unix sockets not supported.
    pass
else:
    HAS_UNIX = True

HAS_IPV6 = False
if socket.has_ipv6:
    # IPv6 must be enabled on Windows XP before it can be used, but
    # socket.has_ipv6 will be True regardless. Check that we can
    # actually create an IPv6 socket.
    try:
        socket.socket(socket.AF_INET6)
    except socket.error:
        pass
    else:
        HAS_IPV6 = True
        SUPPORTED_FAMILIES.append(socket.AF_INET6)

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
            errstr = errno.errorcode[err]
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

    _Channel wraps most common socket methods to make them "safe", more
    consistent in their return values and easier to use in non-blocking
    code. This class is for internal use -- it does not function as-is
    and must be subclassed. Subclasses should override
    :meth:`~pants._channel._Channel._handle_read_event` and
    :meth:`~pants._channel._Channel._handle_write_event` to implement
    basic event-handling behaviour. Subclasses may also override
    :meth:`~pants._channel._Channel._handle_error_event` and
    :meth:`~pants._channel._Channel._handle_hangup_event` to implement
    custom error-handling behaviour. Subclasses should also ensure that
    they call the relevant on_* event handler placeholders at the
    appropriate times.

    =================  ================================================
    Keyword Argument   Description
    =================  ================================================
    engine             *Optional.* The engine to which the channel
                       should be added. Defaults to the global engine.
    socket             *Optional.* A pre-existing socket to wrap.
                       Defaults to a newly-created socket.
    =================  ================================================
    """
    def __init__(self, **kwargs):
        self.engine = kwargs.get("engine", Engine.instance())

        # Socket
        self._socket = None
        self._closed = False
        sock = kwargs.get("socket", None)
        if sock:
            self._socket_set(sock)

        # I/O attributes
        self._recv_amount = 4096

        # Internal state
        self._events = Engine.ALL_EVENTS
        if self._socket:
            self.engine.add_channel(self)

    def __repr__(self):
        return "%s #%r (%s)" % (self.__class__.__name__, self.fileno,
                object.__repr__(self))

    ##### Properties ##########################################################

    @property
    def fileno(self):
        """
        The fileno associated with the socket that this channel wraps,
        or None if the channel does not have a socket.
        """
        return None if not self._socket else self._socket.fileno()

    ##### Control Methods #####################################################

    def close(self, flush=True):
        """
        Close the channel.

        This method does not call the on_close() event handler -
        subclasses are responsible for that functionality.

        =========  =====================================================
        Argument   Description
        =========  =====================================================
        flush      If True, the channel will try to flush any
                   internally buffered data before actually closing.
                   :class:`~pants._channel._Channel` does not do any
                   internal buffering itself, but its subclasses may.
        =========  =====================================================
        """
        if self._closed:
            return

        if self._socket is not None:
            self.engine.remove_channel(self)
            self._socket_close()
        else:
            self._closed = True
        self._events = Engine.ALL_EVENTS
        self._processing_events = False

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

    ##### Public Error Handlers ###############################################

    def on_connect_error(self, exception):
        """
        Placeholder. Called when the channel has failed to connect to a
        remote socket.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close(flush=False)

    def on_read_error(self, exception):
        """
        Placeholder. Called when the channel has failed to read data
        from a remote socket.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close(flush=False)

    def on_write_error(self, exception):
        """
        Placeholder. Called when the channel has failed to write data to
        a remote socket.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close(flush=False)

    def on_overflow_error(self, exception):
        """
        Placeholder. Called when an internal buffer on the channel has
        exceeded its size limit.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close(flush=False)

    def on_error(self, exception):
        """
        Placeholder. Generic error handler for exceptions raised on the
        channel. Called when an error occurs and no specific
        error-handling callback exists.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close(flush=False)

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
        self._socket = sock

    def _socket_connect(self, addr):
        """
        Connect the socket to a remote socket at the given address.

        Returns True if the connection was completed immediately, False
        otherwise.

        =========  ============
        Argument   Description
        =========  ============
        addr       The remote address to connect to.
        =========  ============
        """
        try:
            result = self._socket.connect_ex(addr)
        except socket.error as err:
            result = err[0]

        if not result or result == errno.EISCONN:
            return True

        if result in (errno.EAGAIN, errno.EWOULDBLOCK,
                errno.EINPROGRESS, errno.EALREADY):
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
        if sys.platform == "win32" and backlog > socket.SOMAXCONN:
            log.warning("Setting backlog to SOMAXCONN on %r." % self)
            backlog = socket.SOMAXCONN

        self._socket.listen(backlog)

    def _socket_close(self):
        """
        Close the socket.
        """
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
        except (AttributeError, socket.error):
            return
        finally:
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
        except socket.error as err:
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
        except socket.error as err:
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
        except socket.error as err:
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
        # TODO Find out if socket.send() can return 0 rather than raise
        # an exception if it needs a write event.
        try:
            return self._socket.send(data)
        except Exception as err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._start_waiting_for_write_event()
                return 0
            elif err[0] == errno.EPIPE:
                self.close(flush=False)
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
        except Exception as err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._start_waiting_for_write_event()
                return 0
            elif err[0] == errno.EPIPE:
                self.close(flush=False)
                return 0
            else:
                raise

    def _socket_sendfile(self, sfile, offset, nbytes, fallback=False):
        """
        Send data from a file to a remote socket.

        Returns the number of bytes that were sent to the socket.

        =========  ====================================================
        Argument   Description
        =========  ====================================================
        sfile      The file to send.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all
                   bytes will be written.
        fallback   If True, the pure-Python sendfile function will be
                   used.
        =========  ====================================================
        """
        try:
            return sendfile(sfile, self, offset, nbytes, fallback)
        except Exception as err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._start_waiting_for_write_event()
                return 0
            elif err[0] == errno.EPIPE:
                self.close(flush=False)
                return 0
            else:
                raise

    ##### Internal Methods ####################################################

    def _start_waiting_for_write_event(self):
        """
        Start waiting for a write event on the channel, update the
        engine if necessary.
        """
        if self._events != self._events | Engine.WRITE:
            self._events = self._events | Engine.WRITE
            self.engine.modify_channel(self)

    def _stop_waiting_for_write_event(self):
        """
        Stop waiting for a write event on the channel, update the engine
        if necessary.
        """
        if self._events == self._events | Engine.WRITE:
            self._events = self._events & (self._events ^ Engine.WRITE)
            self.engine.modify_channel(self)

    def _safely_call(self, thing_to_call, *args, **kwargs):
        """
        Safely execute a callable.

        The callable is wrapped in a try block and executed. If an
        exception is raised it is logged.

        If no exception is raised, returns the value returned by
        :func:`thing_to_call`.

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

    def _format_address(self, address):
        """
        Given an address, returns the address family and - if
        necessary - properly formats the address.

        A string is treated as an AF_UNIX address. An integer or long is
        converted to a 2-tuple of the form ('', number). A 2-tuple is
        treated as an AF_INET address and a 4-tuple is treated as an
        AF_INET6 address.

        Will raise an InvalidAddressFormatError if the given address is
        from an unknown or unsupported family.

        ========= ============
        Argument  Description
        ========= ============
        address   The address to format.
        ========= ============
        """
        if isinstance(address, basestring):
            if HAS_UNIX:
                return address, socket.AF_UNIX
            raise InvalidAddressFormatError("AF_UNIX not supported.")

        if isinstance(address, (int, long)):
            address = ('', address)

        try:
            if len(address) == 2:
                return address, socket.AF_INET
            elif len(address) == 4:
                if HAS_IPV6:
                    return address, socket.AF_INET6
                else:
                    raise InvalidAddressFormatError("AF_INET6 not supported.")
        except TypeError:
            # Address does not have a length.
            raise InvalidAddressFormatError("Invalid address: %r" % address)

        # Using %r here can sometimes raise a TypeError.
        raise InvalidAddressFormatError("Invalid address: %s" % repr(address))

    def _resolve_address(self, address, family, cb):
        """
        Use Pants' DNS client to asynchronously resolve the given
        address.

        ========= ===================================================
        Argument  Description
        ========= ===================================================
        address   The address to resolve.
        family    The address family.
        cb        A callable taking two mandatory arguments and one
                  optional argument. The arguments are: the resolved
                  address, the socket family and error information,
                  respectively.
        ========= ===================================================
        """
        # This is here to prevent an import-loop. pants.util.dns depends
        # on pants._channel. Unfortunate, but necessary.
        global dns
        if dns is None:
            from pants.util import dns

        # UNIX addresses and INADDR_ANY don't need to be resolved.
        if isinstance(address, basestring) or address[0] == '':
            cb(address, family)
            return

        def dns_callback(status, cname, ttl, rdata):
            if status == dns.DNS_NAMEERROR:
                cb(None, None, NAME_ERROR)
                return

            if status != dns.DNS_OK or not rdata:
                cb(address, family)
                return

            for i in rdata:
                if ':' in i:
                    if not HAS_IPV6:
                        continue
                    cb((i,) + address[1:], socket.AF_INET6)
                    return
                else:
                    cb((i,) + address[1:], socket.AF_INET)
                    return
            else:
                cb(None, None, FAMILY_ERROR)

        if HAS_IPV6 and family == socket.AF_INET6:
            qtype = dns.AAAA
        else:
            qtype = (dns.AAAA, dns.A)

        dns.query(address[0], qtype, callback=dns_callback)

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

        previous_events = self._events
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
            self._handle_error_event()
            if self._closed:
                return

        if events & Engine.HANGUP:
            self._handle_hangup_event()
            if self._closed:
                return

        if self._events != previous_events:
            self.engine.modify_channel(self)

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

    def _handle_error_event(self):
        """
        Handle an error event raised on the channel.

        By default, logs the error and closes the channel.
        """
        err, errstr = self._get_socket_error()
        if err != 0:
            log.error("Socket error on %r: %s (%d)" % (self, errstr, err))
            self.close(flush=False)

    def _handle_hangup_event(self):
        """
        Handle a hangup event raised on the channel.

        By default, logs the hangup and closes the channel.
        """
        log.debug("Hang up on %r." % self)
        self.close(flush=False)


###############################################################################
# Exceptions
###############################################################################

class InvalidAddressFormatError(Exception):
    """
    Raised when an invalid address format is provided to a channel.
    """
    pass
