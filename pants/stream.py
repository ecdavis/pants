###############################################################################
#
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
Low-level implementations of stream-oriented channels.
"""

###############################################################################
# Imports
###############################################################################

import os
import socket

from pants._channel import _Channel


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Stream Class
###############################################################################

class Stream(_Channel):
    """
    A stream-oriented, connecting channel.

    ==================  ============
    Keyword Arguments   Description
    ==================  ============
    family              *Optional.* A supported socket family. By default, is :const:`socket.AF_INET`.
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
    """
    DATA_STRING = 0
    DATA_FILE = 1

    def __init__(self, **kwargs):
        if kwargs.setdefault("type", socket.SOCK_STREAM) != socket.SOCK_STREAM:
            raise TypeError("Cannot create a %s with a type other than SOCK_STREAM."
                    % self.__class__.__name__)

        _Channel.__init__(self, **kwargs)

        # Socket
        self.remote_addr = None
        self.local_addr = None

        # I/O attributes
        self.read_delimiter = None
        self._recv_buffer = ""
        self._send_buffer = []

        # Channel state
        self.connected = False
        self.connecting = False

    ##### Control Methods #####################################################

    def connect(self, addr):
        """
        Connect the channel to a remote socket.

        Returns the channel.

        ==========  ============
        Arguments   Description
        ==========  ============
        addr        The remote address to connect to.
        ==========  ============
        """
        if self.connected or self.connecting:
            raise RuntimeError("connect() called on active %s #%d."
                    % (self.__class__.__name__, self.fileno))

        if self._socket is None:
            raise RuntimeError("connect() called on closed %s."
                    % self.__class__.__name__)

        self.connecting = True

        try:
            connected = self._socket_connect(addr)
        except socket.error:
            self.close()
            raise

        if connected:
            self._handle_connect_event()

        return self

    def close(self):
        """
        Close the channel.
        """
        if self._socket is None:
            return

        self.read_delimiter = None
        self._recv_buffer = ""
        self._send_buffer = []

        self.connected = False
        self.connecting = False

        self._update_addr()

        _Channel.close(self)

    def end(self):
        """
        Close the channel after writing is finished.
        """
        if self._socket is None:
            return

        if not self._send_buffer:
            self.close()
        else:
            self.on_write = self.close

    ##### I/O Methods #########################################################

    def write(self, data, buffer_data=False):
        """
        Write data to the channel.

        ============  ============
        Arguments     Description
        ============  ============
        data          A string of data to write to the channel.
        buffer_data   If True, the data will be buffered and written later.
        ============  ============
        """
        if self._socket is None:
            log.warning("Attempted to write to closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        if not self.connected:
            log.warning("Attempted to write to disconnected %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        if self._send_buffer and self._send_buffer[-1][0] == Stream.DATA_STRING:
            data_type, existing_data = self._send_buffer.pop(-1)
            data = existing_data + data

        self._send_buffer.append((Stream.DATA_STRING, data))

        if not buffer_data:
            self._process_send_buffer()
        else:
            self._wait_for_write_event = True

    def write_file(self, sfile, nbytes=0, offset=0, buffer_data=False):
        """
        Write a file to the channel.

        ============  ============
        Arguments     Description
        ============  ============
        sfile         A file object to write to the channel.
        nbytes        The number of bytes of the file to write. If 0, all bytes will be written.
        offset        The number of bytes to offset writing by.
        buffer_data   If True, the file will be buffered and written later.
        ============  ============
        """
        if self._socket is None:
            log.warning("Attempted to write file to closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        if not self.connected:
            log.warning("Attempted to write file to disconnected %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        self._send_buffer.append((Stream.DATA_FILE, (sfile, offset, nbytes)))

        if not buffer_data:
            self._process_send_buffer()
        else:
            self._wait_for_write_event = True

    ##### Internal Methods ####################################################

    def _update_addr(self):
        """
        Update the channel's :attr:`~pants.stream.Stream.remote_addr`
        and :attr:`~pants.stream.Stream.local_addr` attributes.
        """
        if self.connected:
            self.remote_addr = self._socket.getpeername()
            self.local_addr = self._socket.getsockname()
        else:
            self.remote_addr = None
            self.local_addr = None

    ##### Internal Event Handler Methods ######################################

    def _handle_read_event(self):
        """
        Handle a read event raised on the channel.
        """
        while True:
            try:
                data = self._socket_recv()
            except socket.error:
                log.exception("Exception raised by recv() on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                # TODO Close this Stream here?
                self.close()
                return

            if data is None:
                self.close()
                return
            elif len(data) == 0:
                break
            else:
                self._recv_buffer += data

        self._process_recv_buffer()

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        if not self.connected:
            self._handle_connect_event()

        if not self._send_buffer:
            return

        self._process_send_buffer()

    def _handle_connect_event(self):
        """
        Handle a connect event raised on the channel.
        """
        self.connecting = False
        err, errstr = self._get_socket_error()
        if err == 0:
            self.connected = True
            self._update_addr()
            self._safely_call(self.on_connect)
        else:
            self._safely_call(self.on_connect_error, (err, errstr))

    ##### Internal Processing Methods #########################################

    def _process_recv_buffer(self):
        """
        Process the :attr:`~pants.stream.Stream._recv_buffer`, passing
        chunks of data to :meth:`~pants.stream.Stream.on_read`.
        """
        while self._recv_buffer:
            delimiter = self.read_delimiter

            if delimiter is None:
                data = self._recv_buffer
                self._recv_buffer = ""
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, (int, long)):
                if len(self._recv_buffer) < delimiter:
                    break
                data = self._recv_buffer[:delimiter]
                self._recv_buffer = self._recv_buffer[delimiter:]
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, basestring):
                mark = self._recv_buffer.find(delimiter)
                if mark == -1:
                    break
                data = self._recv_buffer[:mark]
                self._recv_buffer = self._recv_buffer[mark + len(delimiter):]
                self._safely_call(self.on_read, data)

            else:
                log.warning("Invalid read_delimiter on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                break

            if self._socket is None or not self.connected:
                break

    def _process_send_buffer(self):
        """
        Process the :attr:`~pants.stream.Stream._send_buffer`, passing
        outgoing data to :meth:`~pants._channel._Channel._socket_send`
        or :meth:`~pants._channel._Channel._socket_sendfile` and calling
        :meth:`~pants.stream.Stream.on_write` when sending has finished.
        """
        while self._send_buffer:
            data_type, data = self._send_buffer.pop(0)

            if data_type == Stream.DATA_STRING:
                bytes_sent = self._process_send_data_string(data)
            elif data_type == Stream.DATA_FILE:
                bytes_sent = self._process_send_data_file(*data)

            if bytes_sent == 0:
                break

        if not self._send_buffer:
            self._safely_call(self.on_write)

    def _process_send_data_string(self, data):
        try:
            bytes_sent = self._socket_send(data)
        except socket.error:
            log.exception("Exception raised in send() on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            self.close()
            return 0

        if len(data) > bytes_sent:
            self._send_buffer.insert(0, (Stream.DATA_STRING, data[bytes_sent:]))

        return bytes_sent

    def _process_send_data_file(self, sfile, offset, nbytes):
        try:
            bytes_sent = self._socket_sendfile(sfile, offset, nbytes)
        except socket.error:
            log.exception("Exception raised in sendfile() on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            self.close()
            return 0

        offset += bytes_sent

        if nbytes > 0:
            if nbytes - bytes_sent > 0:
                nbytes -= bytes_sent
            else:
                # Reached the end of the segment.
                return bytes_sent

        if os.fstat(sfile.fileno()).st_size - offset <= 0:
            # Reached the end of the file.
            return bytes_sent

        self._send_buffer.insert(0, (Stream.DATA_FILE, (sfile, offset, nbytes)))

        return bytes_sent


###############################################################################
# StreamServer Class
###############################################################################

class StreamServer(_Channel):
    """
    A stream-oriented, listening channel.

    ==================  ============
    Keyword Arguments   Description
    ==================  ============
    family              *Optional.* A supported socket family. By default, is :const:`socket.AF_INET`.
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
    """
    def __init__(self, **kwargs):
        if kwargs.setdefault("type", socket.SOCK_STREAM) != socket.SOCK_STREAM:
            raise TypeError("Cannot create a %s with a type other than SOCK_STREAM."
                    % self.__class__.__name__)

        _Channel.__init__(self, **kwargs)

        # Socket
        self.remote_addr = None
        self.local_addr = None

        # Channel state
        self.listening = False

    ##### Control Methods #####################################################

    def listen(self, addr, backlog=1024):
        """
        Begin listening for connections made to the channel.

        Returns the channel.

        ==========  ============
        Arguments   Description
        ==========  ============
        addr        The local address to listen for connections on.
        backlog     *Optional.* The size of the connection queue. By default, is 1024.
        ==========  ============
        """
        if self.listening:
            raise RuntimeError("listen() called on active %s #%d."
                    % (self.__class__.__name__, self.fileno))

        if self._socket is None:
            raise RuntimeError("listen() called on closed %s."
                    % self.__class__.__name__)

        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass

        try:
            self._socket_bind(addr)
            self._socket_listen(backlog)
        except socket.error, err:
            self.close()
            raise

        self.listening = True
        self._update_addr()
        self._safely_call(self.on_listen)

        return self

    def close(self):
        """
        Close the channel.
        """
        if self._socket is None:
            return

        self.listening = False

        self._update_addr()

        _Channel.close(self)

    ##### Internal Methods ####################################################

    def _update_addr(self):
        """
        Update the channel's
        :attr:`~pants.stream.StreamServer.remote_addr` and
        :attr:`~pants.stream.StreamServer.local_addr` attributes.
        """
        if self.listening:
            self.remote_addr = None
            self.local_addr = self._socket.getsockname()
        else:
            self.remote_addr = None
            self.local_addr = None

    ##### Internal Event Handler Methods ######################################

    def _handle_read_event(self):
        """
        Handle a read event raised on the channel.
        """
        while True:
            try:
                sock, addr = self._socket_accept()
            except socket.error:
                log.exception("Exception raised by accept() on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                try:
                    sock.close()
                except socket.error:
                    # TODO What do we do here?
                    pass
                # TODO Close this Stream here?
                return

            if sock is None:
                return

            self._safely_call(self.on_accept, sock, addr)

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        log.warning("Received write event for %s #%d." %
                    (self.__class__.__name__, self.fileno))
