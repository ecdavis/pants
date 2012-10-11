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
Low-level implementations of packet-oriented channels.
"""

###############################################################################
# Imports
###############################################################################

import re
import socket
import struct

from pants._channel import _Channel
from pants.util.struct_delimiter import struct_delimiter


###############################################################################
# Constants
###############################################################################

RegexType = type(re.compile(""))


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Datagram Class
###############################################################################

class Datagram(_Channel):
    """
    A packet-oriented channel.

    ==================  ============
    Keyword Arguments   Description
    ==================  ============
    family              *Optional.* A supported socket family. By default, is :const:`socket.AF_INET`.
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
    """
    def __init__(self, **kwargs):
        if kwargs.setdefault("type", socket.SOCK_DGRAM) != socket.SOCK_DGRAM:
            raise TypeError("Cannot create a %s with a type other than "
                "SOCK_DGRAM." % self.__class__.__name__)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        kwargs['socket'] = sock

        _Channel.__init__(self, **kwargs)

        # Socket
        self.remote_address = None
        self.local_address = None

        # I/O attributes
        self.read_delimiter = None
        self.regex_search = True
        self._recv_buffer = {}
        self._recv_buffer_size_limit = 2 ** 16  # 64kb
        self._send_buffer = []

        # Channel state
        self.listening = False
        self._closing = False

    ##### Control Methods #####################################################

    def listen(self, addr):
        """
        Begin listening for packets sent to the channel.

        Returns the channel.

        ==========  ============
        Arguments   Description
        ==========  ============
        addr        The local address to listen for packets on.
        ==========  ============
        """
        if self.listening:
            raise RuntimeError("listen() called on listening %r." % self)

        if self._closed or self._closing:
            raise RuntimeError("listen() called on closed %r." % self)

        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass

        try:
            self._socket_bind(addr)
        except socket.error:
            self.close(flush=False)
            raise

        self.listening = True
        self._update_addr()

        return self

    def close(self, flush=True):
        """
        Close the channel.
        """
        # TODO Implement flushing functionality.
        if self._closed:
            return

        self.read_delimiter = None
        self._recv_buffer = {}
        self._send_buffer = []

        self.listening = False
        self._closing = False

        self._update_addr()

        _Channel.close(self)

    def end(self):
        """
        Close the channel after writing is finished.
        """
        # Integrate into Datagram.close and implement flushing.
        if self._closed or self._closing:
            return

        if not self._send_buffer:
            self.close(flush=False)
        else:
            self._closing = True

    ##### I/O Methods #########################################################

    def write(self, data, address=None, flush=False):
        """
        Write data to the channel.

        ==========  ============
        Arguments   Description
        ==========  ============
        data        A string of data to write to the channel.
        address     The remote address to write the data to.
        flush       If True, flush the internal write buffer.
        ==========  ============
        """
        if self._closed or self._closing:
            log.warning("Attempted to write to closed %r." % self)
            return

        if address is None:
            address = self.remote_address
            if address is None:
                log.warning("Attempted to write to %r with no remote "
                    "address." % self)
                return

        self._send_buffer.append((data, address))

        if flush:
            self._process_send_buffer()
        else:
            self._start_waiting_for_write_event()

    def flush(self):
        """
        Attempt to immediately write any internally buffered data to the
        channel.
        """
        if not self._send_buffer:
            return

        self._stop_waiting_for_write_event()
        self._process_send_buffer()

    ##### Private Methods #####################################################

    def _update_addr(self):
        """
        Update the channel's
        :attr:`~pants.datagram.Datagram.local_address` attribute.
        """
        if self.listening:
            self.local_address = self._socket.getsockname()
        else:
            self.local_address = None

    ##### Internal Event Handler Methods ######################################

    def _handle_read_event(self):
        """
        Handle a read event raised on the channel.
        """
        if self._closed:
            log.warning("Received read event for closed %r." % self)
            return

        if not self.listening:
            log.warning("Received read event for non-listening %r." % self)
            return

        while True:
            try:
                data, addr = self._socket_recvfrom()
            except socket.error:
                log.exception("Exception raised by recvfrom() on %r." % self)
                self.close(flush=False)
                return

            if not data:
                break

            self._recv_buffer[addr] = self._recv_buffer.get(addr, '') + data

            if len(self._recv_buffer[addr]) > self._recv_buffer_size_limit:
                e = DatagramBufferOverflow(
                        "Buffer length exceeded upper limit on %r." % self,
                        addr
                    )
                self._safely_call(self.on_overflow_error, e)
                return

        self._process_recv_buffer()

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        if self._closed:
            log.warning("Received write event for closed %r." % self)
            return

        self._process_send_buffer()

    ##### Internal Processing Methods #########################################

    def _process_recv_buffer(self):
        """
        Process the :attr:`~pants.datagram.Datagram._recv_buffer`, passing
        chunks of data to :meth:`~pants.datagram.Datagram.on_read`.
        """
        for addr in self._recv_buffer.keys()[:]:
            buf = self._recv_buffer[addr]
            self.remote_address = addr

            while buf:
                delimiter = self.read_delimiter

                if delimiter is None:
                    self._safely_call(self.on_read, buf)
                    buf = ""

                elif isinstance(delimiter, (int, long)):
                    if len(buf) < delimiter:
                        break
                    data = buf[:delimiter]
                    buf = buf[delimiter:]
                    self._safely_call(self.on_read, data)

                elif isinstance(delimiter, basestring):
                    mark = buf.find(delimiter)
                    if mark == -1:
                        break
                    data = buf[:mark]
                    buf = buf[mark + len(delimiter):]
                    self._safely_call(self.on_read, data)

                elif isinstance(delimiter, struct_delimiter):
                    # Use item access because it's faster. This'll need to be
                    # changed if struct_delimiter ever changes.
                    if len(buf) < delimiter[1]:
                        break
                    data = buf[:delimiter[1]]
                    buf = buf[delimiter[1]:]

                    try:
                        data = delimiter.unpack(data)
                    except struct.error:
                        log.warning("Unable to unpack data on %r." % self)
                        break

                    self._safely_call(self.on_read, *data)

                elif isinstance(delimiter, RegexType):
                    # Depending on regex_search, we could do this two ways.
                    if self.regex_search:
                        match = delimiter.search(buf)
                        if not match:
                            break

                        data = buf[:match.start()]
                        buf = buf[match.end():]

                    else:
                        data = delimiter.match(buf)
                        if not data:
                            break

                        buf = buf[data.end():]

                    self._safely_call(self.on_read, data)

                else:
                    log.warning("Invalid read_delimiter on %r." % self)
                    break

                if self._closed:
                    break

            self.remote_address = None

            if buf:
                self._recv_buffer[addr] = buf
            else:
                del self._recv_buffer[addr]

            if self._closed:
                break

    def _process_send_buffer(self):
        """
        Process the :attr:`~pants.datagram.Datagram._send_buffer`,
        passing outgoing data to
        :meth:`~pants._channel._Channel._socket_sendto` and calling
        :meth:`~pants.datagram.Datagram.on_write` when sending has
        finished.
        """
        while self._send_buffer:
            data, addr = self._send_buffer.pop(0)

            while data:
                bytes_sent = self._socket_sendto(data, addr)
                self.listening = True
                self._update_addr()
                if bytes_sent == 0:
                    break
                data = data[bytes_sent:]

            if data:
                self._send_buffer.insert(0, (data, addr))
                break

        if not self._send_buffer:
            self._safely_call(self.on_write)

            if self._closing:
                self.close(flush=False)


###############################################################################
# DatagramBufferOverflow Exception
###############################################################################

class DatagramBufferOverflow(Exception):
    def __init__(self, errstr, addr):
        self.errstr = errstr
        self.addr = addr

    def __repr__(self):
        return self.errstr
