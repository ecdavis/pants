###############################################################################
#
# Copyright 2011 Chris Davis
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

import errno
import os
import socket

from pants.reactor import reactor
from pants.shared import log


###############################################################################
# Channel Class
###############################################################################

class Channel(object):
    """
    A raw socket wrapper object.
    
    This class wraps a raw socket object and provides a basic API to
    make socket programming significantly simpler. It handles read,
    write and exception events, has a level of inbuilt error handling
    and calls placeholder methods when certain events occur. The Channel
    class can be subclassed directly, but it is recommended that the
    Server, Connection and Client classes be used to develop networking
    code as they provide slightly less generic APIs.
    """
    def __init__(self, socket=None, parent=None):
        """
        Initialises the channel object.
        
        Args:
            socket: A pre-existing socket that this channel should wrap.
                Optional.
            parent: The reactor that this channel should be attached to.
                Optional.
        """
        # Socket
        self._socket = socket or self._socket_create()
        self._socket.setblocking(False)
        self.fileno = self._socket.fileno()
        
        # Internal state
        self._connected = False
        self._listening = False
        self._closing = False
        
        # Reactor
        self._reactor = parent or reactor
        
        # I/O
        self.read_delimiter = None # String, integer or None.
        self._read_amount = 4096
        self._read_buffer = ""
        self._write_buffer = ""
        
        # Initialisation
        self._events = self._reactor.ERROR
        if self.readable():
            self._events |= self._reactor.READ
        if self.writable():
            self._events |= self._reactor.WRITE
        self._reactor.add_channel(self)
    
    ##### Properties ##########################################################
    
    @property
    def remote_addr(self):
        """
        The remote address to which the channel is connected.
        """
        return self._socket.getpeername()
    
    @property
    def local_addr(self):
        """
        The channel's own address.
        """
        return self._socket.getsockname()
    
    ##### General Methods #####################################################
    
    def active(self):
        """
        Check if the channel is currently active.
        
        Returns:
            True or False
        """
        return self._socket and (self._connected or self._listening)
    
    def readable(self):
        """
        Check if the channel is currently readable.
        
        Returns:
            True or False
        """
        return True
    
    def writable(self):
        """
        Check if the channel is currently writable.
        
        Returns:
            True or False
        """
        return len(self._write_buffer) > 0
    
    def connect(self, host, port):
        """
        Connects to the given host and port.
        
        Args:
            host: The hostname to connect to.
            port: The port to connect to.
        """
        if self.active():
            log.warning("Channel.connect() called on active channel %d." % self.fileno)
            return
        
        self._socket_connect(host, port)
    
    def listen(self, port=8080, host='', backlog=1024):
        """
        Begins listening on the given host and port.
        
        Args:
            port: The port to listen on. Defaults to 8080.
            host: The hostname to listen on. Defaults to ''.
            backlog: The maximum number of queued connections. Defaults
                to 1024.
        """
        if self.active():
            log.warning("Channel.listen() called on active channel %d." % self.fileno)
            return
        
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket_bind(host, port)
        self._socket_listen(backlog)
    
    def close(self):
        """
        Close the socket.
        
        Currently pending data will be sent, any further data will not
        be sent.
        """
        if not self.active():
            return
        
        if self.writable():
            self._closing = True
        else:
            self.close_immediately()
    
    def close_immediately(self):
        """
        Close the socket immediately.
        
        Any pending data will not be sent.
        """
        if not self.active():
            return
        
        self._reactor.remove_channel(self)
        self._socket_close()
        self._safely_call(self.handle_close)
    
    ##### I/O Methods #########################################################
    
    def send(self, data):
        """
        A wrapper for Channel.write() that can be safely overridden.
        
        Args:
            data: The data to be sent.
        """
        self.write(data)
    
    def write(self, data):
        """
        Writes data to the socket.
        
        Args:
            data: The data to be sent.
        """
        if not self.active():
            raise IOError("Attempted to write to closed channel %d." % self.fileno)
        if self._closing:
            log.warning("Attempted to write to closing channel %d." % self.fileno)
            return
        
        self._write_buffer += data
        
        if not self._events & self._reactor.WRITE:
            self._events |= self._reactor.WRITE
            self._reactor.modify_channel(self)
    
    ##### Public Event Handlers ###############################################
    
    def handle_read(self, data):
        """
        Placeholder. Called when the channel is ready to receive data.
        
        Args:
            data: The chunk of received data.
        """
        pass
    
    def handle_write(self):
        """
        Placeholder. Called when the channel is ready to write data.
        """
        pass
    
    def handle_accept(self, socket, addr):
        """
        Placeholder. Called when a new connection has been made to the
        channel.
        
        Args:
            socket: The newly-connected socket object.
            addr: The socket's address.
        """
        pass
    
    def handle_connect(self):
        """
        Placeholder. Called after the channel has connected to a remote
        host.
        """
        pass
    
    def handle_close(self):
        """
        Placeholder. Called when the channel is about to close.
        """
        pass
    
    ##### Socket Method Wrappers ##############################################
    
    def _socket_create(self, family=socket.AF_INET, type=socket.SOCK_STREAM):
        """
        Wrapper for socket.socket().
        
        Args:
            family: The address family. Defaults to AF_INET.
            type: The socket type. Defaults to SOCK_STREAM.
        
        Returns:
            A new socket object.
        """
        return socket.socket(family, type)
    
    def _socket_connect(self, host, port):
        """
        Wrapper for self._socket.connect().
        
        Args:
            host: The hostname to connect to.
            port: The port to connect to.
        """
        self._connected = False
        
        try:
            self._socket.connect((host, port))
            # A write event is raised when the connection has completed.
            self._events |= self._reactor.WRITE
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                # EAGAIN: Try again.
                # EWOULDBLOCK: Operation would block.
                return # TODO Return False to indicate failure to connect?
            elif err[0] in (errno.EALREADY, errno.EINPROGRESS):
                # EALREADY: Operation already in progress.
                # EINPROGRESS: Operation now in progress.
                return
            elif err[0] in (0, errno.EISCONN):
                # 0: No error.
                # EISCONN: Transport endpoint is already connected.
                self._handle_connect_event()
            else:
                raise
    
    def _socket_bind(self, host, port):
        """
        Wrapper for self._socket.bind().
        
        Args:
            host: The hostname to bind to.
            port: The port to bind to.
        """
        self._socket.bind((host, port))
    
    def _socket_listen(self, backlog=5):
        """
        Wrapper for self._socket.listen().
        
        Args:
            backlog: The maximum number of queued connections. Defaults
                to 5.
        """
        self._listening = True
        
        if os.name == "nt" and backlog > 5:
            backlog = 5
        
        self._socket.listen(backlog)
    
    def _socket_close(self):
        """
        Wrapper for self._socket.close().
        """
        self._connected = False
        self._listening = False
        
        try:
            self._socket.close()
        except AttributeError:
            # self._socket is None - closed already.
            return
        except socket.error, err:
            if err[0] in (errno.EBADF, errno.ENOTCONN):
                # EBADF: Bad file number.
                # ENOTCONN: Transport endpoint is not connected.
                return
            else:
                raise
        finally:
            self._socket = None
    
    def _socket_accept(self):
        """
        Wrapper for self._socket.accept().
        
        Returns:
            A 2-tuple (sock, addr). sock is None if an exception was
            raised by self._socket.accept().
        """
        try:
            return self._socket.accept()
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                # EAGAIN: Try again.
                # EWOULDBLOCK: Operation would block.
                return None, () # sock, addr
            else:
                raise
    
    def _socket_send(self, data):
        """
        Wrapper for self._socket.send().
        
        Args:
            data: The data to be sent.
        
        Returns:
            The number of bytes sent.
        """
        try:
            return self._socket.send(data)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                # EAGAIN: Try again.
                # EWOULDBLOCK: Operation would block.
                return 0
            elif err[0] in (errno.ECONNABORTED, errno.ECONNRESET,
                            errno.ENOTCONN, errno.ESHUTDOWN):
                # ECONNABORTED: Software caused connection abort.
                # ECONNRESET: Connection reset by peer.
                # ENOTCONN: Transport endpoint is not connected.
                # ESHUTDOWN: Cannot send after transport endpoint shutdown.
                self.close_immediately()
                return 0
            else:
                raise
    
    def _socket_recv(self):
        """
        Wrapper for self._socket.recv().
        
        Returns:
            The data received.
        """
        try:
            data = self._socket.recv(self._read_amount)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                # EAGAIN: Try again.
                # EWOULDBLOCK: Operation would block.
                return ''
            elif err[0] in (errno.ECONNABORTED, errno.ECONNRESET,
                            errno.ENOTCONN, errno.ESHUTDOWN,):
                # ECONNABORTED: Software caused connection abort.
                # ECONNRESET: Connection reset by peer.
                # ENOTCONN: Transport endpoint is not connected.
                # ESHUTDOWN: Cannot send after transport endpoint shutdown.
                self.close_immediately()
                return ''
            else:
                raise
        
        if not data:
            # A closed connection is signalled by a read condition
            # and having recv() return an empty string.
            self.close_immediately()
            return ''
        else:
            return data
    
    ##### Internal Event Handlers #############################################
    
    def _handle_events(self, events):
        """
        Args:
            events: The events raised on the channel.
        """
        if self._socket is None:
            log.warning("Received events for closed channel %d." % self.fileno)
            return
        elif not self.active():
            # TODO Fix this properly. How to handle events on newly
            # connected channels?
            log.debug("Received events for closed channel %d." % self.fileno)
        
        # Read event.
        if events & self._reactor.READ:
            if self._listening:
                self._handle_accept_event()
            elif not self._connected:
                self._handle_connect_event()
            else:
                self._handle_read_event()
            if not self.active():
                return
        
        # Write event.
        if events & self._reactor.WRITE:
            self._handle_write_event()
            if not self.active():
                return
        
        # Error event.
        if events & self._reactor.ERROR:
            self.close_immediately()
            return
        
        # Update events.
        events = self._reactor.ERROR
        if self.readable():
            events |= self._reactor.READ
        if self.writable():
            events |= self._reactor.WRITE
        elif self._closing:
            # Done writing, so close.
            self.close_immediately()
            return
        
        if events != self._events:
            self._events = events
            self._reactor.modify_channel(self)
    
    def _handle_accept_event(self):
        while True:
            sock, addr = self._socket_accept()
            
            if sock is None:
                return
            
            self._safely_call(self.handle_accept, sock, addr)
    
    def _handle_connect_event(self):
        self._connected = True
        self._safely_call(self.handle_connect)
    
    def _handle_read_event(self):
        # Receive incoming data.
        while True:
            data = self._socket_recv()
            if not data:
                break
            self._read_buffer += data
        
        # Handle incoming data.
        while self._read_buffer:
            delimiter = self.read_delimiter
            
            if delimiter is None:
                data = self._read_buffer
                self._read_buffer = ""
                self._safely_call(self.handle_read, data)
                
            elif isinstance(delimiter, (int, long)):
                if len(self._read_buffer) < delimiter:
                    break
                
                data = self._read_buffer[:delimiter]
                self._read_buffer = self._read_buffer[delimiter:]
                self._safely_call(self.handle_read, data)
                
            elif isinstance(delimiter, basestring):
                mark = self._read_buffer.find(delimiter)
                if mark == -1:
                    break
                
                data = self._read_buffer[:mark]
                self._read_buffer = self._read_buffer[mark+len(delimiter):]
                self._safely_call(self.handle_read, data)
            
            else:
                log.warning("Invalid read_delimiter on channel %d." % self.fileno)
                break
            
            if not self.active():
                break
    
    def _handle_write_event(self):
        if self._listening:
            log.warning("Received write event for listening channel %d." % self.fileno)
            return
        
        if not self._connected:
            # socket.connect() has completed, returning either 0 or an errno.
            err = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                self._safely_call(self._handle_connect_event())
            else:
                errstr = "Unknown error %d" % err
                try:
                    errstr = os.strerror(err)
                except (NameError, OverflowError, ValueError):
                    if err in errno.errorcode:
                        errstr = errno.errorcode[err]
                
                raise socket.error(err, errstr)
            
            # Write events are raised on clients when they initially
            # connect. In these circumstances, we may not need to write
            # any data, so we check.
            if not self.writable():
                return
        
        # Empty as much of the write buffer as possible.
        while self._write_buffer:
            sent = self._socket_send(self._write_buffer)
            if sent == 0:
                break
            self._write_buffer = self._write_buffer[sent:]
        
        self._safely_call(self.handle_write)
    
    def _safely_call(self, callable, *args, **kwargs):
        """
        Args:
            callable: The callable to execute.
            *args: Positional arguments to pass to the callable.
            **kwargs: Keyword arguments to pass to the callable.
        """
        try:
            callable(*args, **kwargs)
        except Exception:
            log.exception("Exception raised on channel %d." % self.fileno)
            self.close_immediately()
