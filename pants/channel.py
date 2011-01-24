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
        
        Parameters:
            socket - A pre-existing socket that this channel should
                wrap. Optional.
        """
        # Socket
        self.socket = socket or self.socket_create()
        self.socket.setblocking(False)
        self.fileno = self.socket.fileno()
        
        # State
        self.connected = False
        self.listening = False
        self.closing = False
        
        # Reactor
        self.reactor = parent or reactor
        
        # I/O
        self._read_amount = 4096
        self._read_delimiter = None # str, int or None
        self._read_buffer = ""
        self._write_buffer = ""
        
        # Initialisation
        self.events = self.reactor.ERROR
        if self.readable():
            self.events |= self.reactor.READ
        if self.writable():
            self.events |= self.reactor.WRITE
        self.reactor.add_channel(self)
    
    ##### General Methods ###################################################
    
    def active(self):
        """
        Returns True if the channel is currently active.
        """
        return self.socket and (self.connected or self.listening)
    
    def readable(self):
        """
        Returns True if the channel is currently readable.
        """
        return True
    
    def writable(self):
        """
        Returns True if the channel is currently readable.
        """
        return len(self._write_buffer) > 0
    
    def connect(self, host, port):
        """
        Connects to the given host and port.
        
        Parameters:
            host - A string hostname to connect to.
            port - An integer port to connect to the host on.
        """
        self.socket_connect(host, port)
    
    def listen(self, port=8080, host='', backlog=1024):
        """
        Begins listening on the given host and port.
        
        Parameters:
            port - An integer port to listen on. Defaults to 8080.
            host - A string hostname to listen on. Defaults to ''.
            backlog - The number of new connections kept in the backlog.
                Defaults to 1024. 5 is the upper limit on Windows.
        """
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_bind(host, port)
        self.socket_listen(backlog)
    
    def close(self):
        """
        Close the socket.
        
        Currently pending data will be sent, any further data will not
        be sent.
        """
        if not self.active():
            return
        
        if self.writable():
            self.closing = True
        else:
            self.close_immediately()
    
    def close_immediately(self):
        """
        Close the socket immediately.
        
        Any pending data will not be sent.
        """
        if not self.active():
            return
        
        self.reactor.remove_channel(self)
        self.socket_close()
        self._safely_call(self.handle_close)
    
    ##### I/O Methods #########################################################
    
    def write(self, data):
        """
        Writes data to the socket.
        
        Parameters:
            data - A string containing the data to be sent to the
                socket.
        """
        if not self.active():
            raise IOError("Attempted to write to closed channel %d." % self.fileno)
        if self.closing:
            log.warning("Attempted to write to closing channel %d." % self.fileno)
            return
        
        self._write_buffer += data
        
        if not self.events & self.reactor.WRITE:
            self.events |= self.reactor.WRITE
            self.reactor.modify_channel(self)
    
    ##### Public Event Handlers ###############################################
    
    def handle_read(self, data):
        """
        Placeholder. Called when the channel is ready to receive data.
        """
        pass
    
    def handle_write(self):
        """
        Placeholder. Called when the channel is ready to write data.
        """
        pass
    
    def handle_accept(self, sock, addr):
        """
        Placeholder. Called when a new connection has been made to the
        channel.
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
    
    def socket_create(self, family=socket.AF_INET, type=socket.SOCK_STREAM):
        """
        Creates a new socket with the given family and type.
        
        Parameters:
            family - The socket family. Defaults to AF_INET.
            type - The socket type. Defaults to SOCK_STREAM.
        """
        return socket.socket(family, type)
    
    def socket_connect(self, host, port):
        """
        Connects the socket to the given host and port.
        
        Parameters:
            host - A string hostname to connect to.
            port - An integer port to connect to the host on.
        """
        self.connected = False
        
        try:
            self.socket.connect((host, port))
            self.events |= self.reactor.WRITE
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
    
    def socket_listen(self, backlog=5):
        """
        Starts the socket listening, if it has been bound.
        """
        self.listening = True
        
        if os.name == "nt" and backlog > 5:
            backlog = 5
        
        return self.socket.listen(backlog)
    
    def socket_bind(self, host, port):
        """
        Binds the socket to the given host and port.
        
        Parameters:
            host - A string hostname to bind to.
            port - An integer port to bind on.
        """
        return self.socket.bind((host, port))
    
    def socket_close(self):
        """
        Closes the socket's connection.
        """
        self.connected = False
        self.listening = False
        
        try:
            self.socket.close()
        except AttributeError:
            # self.socket is None - closed already.
            return
        except socket.error, err:
            if err[0] in (errno.EBADF, errno.ENOTCONN):
                # EBADF: Bad file number.
                # ENOTCONN: Transport endpoint is not connected.
                return
            else:
                raise
        finally:
            self.socket = None
    
    def socket_accept(self):
        """
        Accepts a new connection to the socket.
        """
        try:
            return self.socket.accept()
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                # EAGAIN: Try again.
                # EWOULDBLOCK: Operation would block.
                return None, () # sock, addr
            else:
                raise
    
    def socket_send(self, data):
        """
        Sends raw data to the socket.
        
        Parameters:
            data - A string containing the data to be sent.
        """
        try:
            return self.socket.send(data)
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
    
    def socket_recv(self):
        """
        Reads raw data from the socket.
        """
        try:
            data = self.socket.recv(self._read_amount)
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
        if not self.active():
            log.warning("Received events for closed channel %d." % self.fileno)
        
        # Handle events.
        if events & self.reactor.READ:
            if self.listening:
                self._handle_accept_event()
            elif not self.connected:
                self._handle_connect_event()
            else:
                self._handle_read_event()
            if not self.active():
                return
        
        if events & self.reactor.WRITE:
            self._handle_write_event()
            if not self.active():
                return
        
        if events & self.reactor.ERROR:
            self.close_immediately()
            return
        
        # Update events.
        events = self.reactor.ERROR
        if self.readable():
            events |= self.reactor.READ
        if self.writable():
            events |= self.reactor.WRITE
        elif self.closing:
            # Done writing? Close.
            self.close_immediately()
            return
        
        if events != self.events:
            self.events = events
            self.reactor.modify_channel(self)
    
    def _handle_accept_event(self):
        while True:
            sock, addr = self.socket_accept()
            
            if sock is None:
                return
            
            self._safely_call(self.handle_accept, sock, addr)
    
    def _handle_connect_event(self):
        self.connected = True
        self._safely_call(self.handle_connect)
    
    def _handle_read_event(self):
        # Receive incoming data.
        while True:
            data = self.socket_recv()
            if not data:
                break
            self._read_buffer += data
        
        # Handle incoming data.
        while self._read_buffer:
            delimiter = self._read_delimiter
            
            if delimiter is None:
                data = self._read_buffer
                self._read_buffer = ""
                self._safely_call(self.handle_read, data)
                
            elif isinstance(delimiter, (int, long)):
                if len(self._read_buffer) < delimiter:
                    break
                
                data = self._read_buffer[:delimiter]
                self._read_buffer = self._read_buffer[delimiter:]
                # TODO Reset delimiter here?
                self._safely_call(self.handle_read, data)
                
            elif isinstance(delimiter, basestring):
                mark = self._read_buffer.find(delimiter)
                if mark == -1:
                    break
                
                data = self._read_buffer[:mark]
                self._read_buffer = self._read_buffer[mark+len(delimiter):]
                # TODO Reset delimiter here?
                self._safely_call(self.handle_read, data)
            
            else:
                log.warning("Invalid _read_delimiter on channel %d." % self.fileno)
                break
            
            if not self.active():
                break
    
    def _handle_write_event(self):
        if self.listening:
            log.warning("Received write event for listening channel %d." % self.fileno)
            return
        
        if not self.connected:
            # socket.connect() has completed, returning either 0 or an errno.
            err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                self._safely_call(self._handle_connect_event())
            else:
                errstr = "Unknown error %" % e
                try:
                    errstr = os.strerror(e)
                except (NameError, OverflowError, ValueError):
                    if e in errno.errorcode:
                        errstr = errno.errorcode[e]
                
                raise socket.error(e, errstr)
            
            # Write events are raised on clients when they initially
            # connect. In these circumstances, we may not need to write
            # any data.
            if not self.writable():
                return
        
        self._safely_call(self.handle_write)
        
        while self._write_buffer:
            # Empty as much of the write buffer as possible.
            sent = self.socket_send(self._write_buffer)
            
            if sent == 0:
                break
            self._write_buffer = self._write_buffer[sent:]
    
    def _safely_call(self, callable, *args, **kwargs):
        try:
            callable(*args, **kwargs)
        except Exception, e:
            self.close_immediately()
            raise
