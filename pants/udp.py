###############################################################################
#
# Copyright 2011 Stendec <stendec365@gmail.com>
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
import socket

from pants.engine import Engine


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# UDPChannel Class
###############################################################################

class UDPChannel(object):
    """
    A UDP socket wrapper object.
    
    This class wraps around a raw socket object and provides a basic API for
    making UDP programming much easier, while trying to remain true to the
    Pants API presented by the Channel object.
    
    Note that for merely sending UDP messages, you don't have to use a
    UDPChannel, and can instead use pants.send_udp(data, addr).
    """
    def __init__(self, socket=None):
        """
        Initializes the UDPChannel object.
        
        Args:
            socket: A pre-existing socket that this UDPChannel should wrap.
                Optional.
        """
        self._socket = socket or self._socket_create()
        self._socket.setblocking(False)
        self.fileno = self._socket.fileno()
        self.remote_addr = (None, None)
        self.local_addr = (None, None)
        
        # Internal State
        self._listening = False
        self._closing = False
        
        # Input
        self.read_delimiter = None
        self._read_amount = 4096
        self._read_buffer = {}
        
        # Output
        self._write_buffer = []
        
        # Initialization
        self._events = Engine.ERROR
        if self.readable():
            self._events |= Engine.READ
        if self.writable():
            self._events |= Engine.WRITE
        Engine.instance().add_channel(self)
    
    ##### General Methods #####################################################
    
    def active(self):
        """
        Checks if the channel is currently active. Basically, if it's either
        got data in its write buffer, or if it's listening.
        
        Returns:
            True or False
        """
        return self._socket and (self._listening or self._write_buffer)
    
    def readable(self):
        """
        Checks if the channel is currently readable.
        
        Returns:
            True or False
        """
        return self._listening and not self._closing
    
    def writable(self):
        """
        Checks if the channel is currently writable.
        
        Returns:
            True or False
        """
        return len(self._write_buffer) > 0
    
    def connect(self, host, port):
        raise NotImplementedError
    
    def listen(self, port=8080, host='', backlog=1024):
        """
        Begins listening on the given host and port.
        
        Args:
            port: The port to listen on. Defaults to 8080.
            host: The hostname to listen on. Defaults to ''.
            backlog: The maximum number of queued connections. Defaults to
                1024.
        
        Returns:
            The UDPChannel object.
        """
        if self._listening:
            log.warning("UDPChannel.listen() called on active UDPChannel %d." % self.fileno)
            return self
        
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        
        self._socket_bind(host, port)
        
        self._listening = True
        self._update_addr()
        self._add_event(Engine.READ)
        
        return self
    
    def close(self):
        """
        Close the UDPChannel.
        
        Currently pending data will be sent, and any further data will not be
        sent.
        """
        if not self.active():
            return
        
        if self.writable():
            self._closing = True
        else:
            self.close_immediately()
    
    def close_immediately(self):
        """
        Close the UDPChannel immediately.
        
        Any pending data will not be sent.
        """
        if not self.active():
            return
        
        Engine.instance().remove_channel(self)
        self._socket_close()
        self._update_addr()
        self._safely_call(self.handle_close)
    
    ##### I/O Methods #########################################################
    
    def send(self, data, addr=None):
        """
        Overridable wrapper for UDPChannel.write()
        
        Args:
            data: The data to be sent.
            addr: The address to send it to. If called within handle_read and
                addr is None, it'll be assumed to send the data to whichever
                address the data being handled came from.
        """
        self.write(data, addr)
    
    def write(self, data, addr=None):
        """
        Writes data to the given address.
        
        Args:
            data: The data to be sent.
            addr: The address to send it to. If called within handle_read and
                addr is None, it'll be assumed to send the data to whichever
                address the data being handled came from.
        """
        if not self._socket:
            raise IOError("Attempted to write to closed UDPChannel %d." % self.fileno)
        if self._closing:
            log.warning("Attempted to write to closing UDPChannel %d." % self.fileno)
            return
        
        if addr is None:
            addr = self.remote_addr
            if addr[0] is None:
                raise IOError("Attempted to write with no remote address.")
        
        self._write_buffer.append((data, addr))
        self._add_event(Engine.WRITE)
    
    ##### Public Event Handlers ###############################################
    
    def handle_read(self, data):
        """
        Placeholder. Called when the channel has recieved a new UDP datagram.
        
        Args:
            data: The chunk of received data.
        """
        pass
    
    def handle_write(self):
        """
        Placeholder. Called after the channel has written data.
        """
        pass
    
    def handle_close(self):
        """
        Placeholder. Called when the channel is about to close.
        """
        pass
    
    ##### Private Methods #####################################################
    
    def _add_event(self, event):
        if not self._events & event:
            self._events |= event
            Engine.instance().modify_channel(self)
    
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
            log.exception("Exception raised on UDPChannel %d." % self.fileno)
            self.close_immediately()
    
    def _update_addr(self):
        if self._listening:
            self.local_addr = self._socket.getsockname()
        else:
            self.local_addr = (None, None)
    
    ##### Socket Method Wrappers ##############################################
    
    def _socket_create(self, family=socket.AF_INET, type=socket.SOCK_DGRAM):
        """
        Wrapper for socket.socket().
        
        Args:
            family: The address family. Defaults to AF_INET.
            type: The socket type. Defaults to SOCK_DGRAM.
        
        Returns:
            A new socket object.
        """
        return socket.socket(family, type)
    
    def _socket_bind(self, host, port):
        """
        Wrapper for self._socket.bind().
        
        Args:
            host: The hostname to bind to.
            port: The port to bind to.
        """
        self._socket.bind((host, port))
    
    def _socket_close(self):
        """
        Wrapper for self._socket.close().
        """
        self._listening = False
        
        try:
            self._socket.close()
        except AttributeError:
            return
        except socket.error, err:
            if err[0] in (errno.EBADF, errno.ENOTCONN):
                return
            else:
                raise
        finally:
            self._socket = None
    
    def _socket_sendto(self, data, addr):
        """
        Wrapper for self._socket.sendto().
        
        Args:
            data: The data to be sent.
            addr: The address to send the data to.
        
        Returns:
            The number of bytes sent.
        """
        try:
            return self._socket.sendto(data, addr)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return 0
            elif err[0] in (errno.ECONNABORTED, errno.ECONNRESET,
                            errno.ENOTCONN, errno.ESHUTDOWN):
                self.close_immediately()
                return 0
            else:
                raise
    
    def _socket_recvfrom(self):
        """
        Wrapper for self._socket.recvfrom().
        
        Returns:
            data, addr
        """
        try:
            data, addr = self._socket.recvfrom(self._read_amount)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return '', (None, None)
            elif err[0] in (errno.ECONNABORTED, errno.ECONNRESET,
                            errno.ENOTCONN, errno.ESHUTDOWN):
                self.close_immediately()
                return '', (None, None)
            else:
                raise
        
        if not data:
            self.close_immediately()
            return '', (None, None)
        else:
            return data, addr
    
    ##### Private Event Handlers ##############################################
    
    def _handle_events(self, events):
        if not self._socket:
            log.warning("Received events for closed UDPChannel %d." % self.fileno)
            return
        
        # Read Event
        if events & Engine.READ:
            self._handle_read_event()
            if not self._socket:
                return
        
        # Write Event
        if events & Engine.WRITE:
            self._handle_write_event()
            if not self._socket:
                return
        
        # Error Event
        if events & Engine.ERROR:
            self.close_immediately()
            return
        
        # Update Events
        events = Engine.ERROR
        if self.readable():
            events |= Engine.READ
        if self.writable():
            events |= Engine.WRITE
        elif self._closing:
            self.close_immediately()
            return
        
        if events != self._events:
            self._events = events
            Engine.instance().modify_channel(self)
    
    def _handle_read_event(self):
        while True:
            data, addr = self._socket_recvfrom()
            if not data:
                break
            self._read_buffer[addr] = self._read_buffer.get(addr, '') + data
        
        delim = self.read_delimiter
        
        for k in self._read_buffer.keys():
            buf = self._read_buffer[k]
            self.remote_addr = k
            
            while buf:
                if delim is None:
                    self._safely_call(self.handle_read, buf)
                    buf = ''
                
                elif isinstance(delim, (int,long)):
                    if len(buf) < delim:
                        break
                    
                    data = buf[:delim]
                    buf = buf[delim:]
                    self._safely_call(self.handle_read, data)
                
                elif isinstance(delim, basestring):
                    mark = buf.find(delim)
                    if mark == -1:
                        break
                    
                    data = buf[:mark]
                    buf = buf[mark+len(delim):]
                    self._safely_call(self.handle_read, data)
                
                else:
                    log.warning("Invalid read_delimiter on UDPChannel %d." % self.fileno)
                    break
            
            self.remote_addr = (None, None)
                
            if buf:
                self._read_buffer[k] = buf
            else:
                del self._read_buffer[k]
        
    def _handle_write_event(self):
        # Empty as much of the write buffer as possible.
        while self._write_buffer:
            data, addr = self._write_buffer.pop(0)
            while data:
                sent = self._socket_sendto(data, addr)
                if sent == 0:
                    break
                data = data[sent:]
            
            if data:
                self._write_buffer.insert(0, (data, addr))
                break
        
        self._safely_call(self.handle_write)

###############################################################################
# sendto Function
###############################################################################

_channel = None

def sendto(data, host, port):
    """
    Send a UDP datagram with the given data to the provided host and port. This
    automatically constructs a UDPChannel and handles that for you, so you can
    send data simply.
    
    Args:
        data: The data to send.
        host: The host to send the data to.
        port: The port to send the data to.
    """
    global _channel
    if _channel is None:
        _channel = UDPChannel()
    _channel.write(data, (host, port))
