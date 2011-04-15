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

from pants.engine import Engine


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Channel Class
###############################################################################

class Channel(object):
    """
    """
    def __init__(self, **kwargs):
        # Keyword arguments
        sock = kwargs.get("socket", None)
        sock_family = kwargs.get("family", socket.AF_INET)
        sock_type = kwargs.get("type", socket.SOCK_STREAM)
        
        # Socket
        self._socket = sock or self._socket_create(sock_family, sock_type)
        self.fileno = self._socket.fileno()
        self.remote_addr = (None, None)
        self.local_addr = (None, None)
        
        # I/O attributes
        self._recv_amount = 4096
        self._recv_buffer = ""
        self._recv_delimiter = None
        self._send_buffer = ""
        
        # Events
        self._events = Engine.ERROR | Engine.READ | Engine.WRITE
        Engine.instance().add_channel(self)
    
    ##### Status Methods ######################################################
    
    def closed(self):
        """
        Returns True if the Channel is closed.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    ##### Control Methods #####################################################
    
    def connect(self, *args, **kwargs):
        """
        Connects the channel to a remote socket.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    def listen(self, *args, **kwargs):
        """
        Begins listening for connections made to the channel.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    def close(self, *args, **kwargs):
        """
        Closes the channel.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    def end(self, *args, **kwargs):
        """
        Closes the stream after writing any pending data to the socket.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    ##### I/O Methods #########################################################
    
    def read(self, *args, **kwargs):
        """
        """
        raise NotImplementedError
    
    def read_until(self, *args, **kwargs):
        """
        """
        raise NotImplementedError
    
    def read_bytes(self, *args, **kwargs):
        """
        """
        raise NotImplementedError
    
    def _recv(self, *args, **kwargs):
        """
        """
        raise NotImplementedError
    
    def write(self, *args, **kwargs):
        """
        """
        raise NotImplementedError
    
    def _send(self, *args, **kwargs):
        """
        """
        raise NotImplementedError
    
    ##### Public Event Handlers ###############################################
    
    def on_read(self, data):
        """
        """
        pass
    
    def on_write(self):
        """
        """
        pass
    
    def on_connect(self):
        """
        """
        pass
    
    def on_accept(self, socket, addr):
        """
        """
        pass
    
    def on_close(self):
        """
        """
        pass
    
    ##### Socket Method Wrappers ##############################################
    
    def _socket_create(self, socket_family, socket_type):
        """
        Returns a new non-blocking socket with the given family and type.
        """
        if socket_family not in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
            raise ValueError("Specified socket family is not supported.")
        elif socket_family == socket.AF_UNIX and not hasattr(socket, "AF_UNIX"):
            raise ValueError("Specified socket family is not supported.")
        if socket_type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            raise ValueError("Specified socket type is not supported.")
        
        sock = socket.socket(socket_family, socket_type)
        sock.setblocking(False)
        self.fileno = sock.fileno()
        
        return sock
    
    def _socket_connect(self, addr):
        """
        Connects the socket to a remote socket at the given address.
        Returns True if the connection was immediate, False otherwise.
        """
        try:
            result = self._socket.connect_ex(addr)
        except socket.error, err:
            result = err[0]
        
        if not result or result == errno.EISCONN:
            return True
        
        if result in (errno.EINPROGRESS, errno.EALREADY):
            # TODO Check for EAGAIN, EWOULDBLOCK here?
            self._add_event(Engine.WRITE)
            return False
        
        try:
            errstr = os.strerror(result)
        except ValueError:
            if result in errno.errorcode:
                errstr = errno.errorcode[result]
            else:
                errstr = "Unknown error %d." % result
        
        raise socket.error(result, errstr)
    
    def _socket_bind(self, addr):
        """
        Binds the socket to the given address. The address format should
        be correct for the socket's family.
        """
        self._socket.bind(addr)
    
    def _socket_listen(self, backlog):
        """
        Begins listening for connections made to the socket.
        """
        if os.name == "nt" and backlog > 5:
            log.warning("Setting backlog to 5 due to OS constraints.")
            backlog = 5
        
        self._socket.listen(backlog)
    
    def _socket_close(self):
        """
        Closes the socket.
        """
        try:
            self._socket.close()
        except (AttributeError, socket.error):
            return
        finally:
            self._socket = None
            self.fileno = None
    
    def _socket_accept(self):
        """
        Accepts a new connection to the socket.
        """
        try:
            return self._socket.accept()
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return None, () # sock, addr placeholders.
            else:
                raise
    
    def _socket_recv(self):
        """
        Returns a string of data read from the socket or None if the
        connection has been closed.
        """
        try:
            data = self._socket.recv(self._recv_amount)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return ''
            else:
                raise
        
        if not data:
            return None
        else:
            return data
    
    def _socket_recvfrom(self):
        """
        Returns a string of data read from the socket and the address of
        the sender. The data is None if reading failed. The address is
        None if no data was received.
        """
        try:
            data, addr = self._socket.recvfrom(self._recv_amount)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return '', None
            else:
                raise
        
        # TODO Is this section necessary?
        if not data:
            return None, None
        else:
            return data, addr
    
    def _socket_send(self, data):
        """
        Returns the number of bytes that were sent to the socket.
        """
        try:
            return self._socket.send(data)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return 0
            else:
                raise
    
    def _socket_sendto(self, data, addr):
        """
        Returns the number of bytes that were sent to the socket.
        """
        try:
            return self._socket.sendto(data, addr)
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return 0
            else:
                raise
    
    ##### Internal Methods ####################################################
    
    def _add_event(self, event):
        """
        Adds an event to the channel and updates the engine.
        """
        if not self._events & event:
            self._events |= event
            Engine.instance().modify_channel(self)
    
    def _safely_call(self, thing_to_call, *args, **kwargs):
        """
        Wraps a callable in a try block. If an exception is raised it is
        logged and the channel is closed.
        """
        if thing_to_call is None:
            return
        
        try:
            return thing_to_call(*args, **kwargs)
        except Exception:
            log.exception("Exception raised on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            self.close()
    
    def _update_addr(self):
        """
        Updates the channel's remote_addr and local_addr attributes.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    ##### Internal Event Handler Methods ######################################
    
    def _handle_events(self, events):
        """
        Handles events raised on the channel.
        """
        if self.closed():
            log.warning("Received events for closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return
        
        if events & Engine.READ:
            self._handle_read_event()
            if self.closed():
                return
        
        if events & Engine.WRITE:
            self._handle_write_event()
            if self.closed():
                return
        
        if events & Engine.ERROR:
            # TODO Should we log this?
            # TODO Should this be above the read/write event handling?
            self.close()
            return
        
        events = Engine.ERROR | Engine.READ
        if self._send_buffer:
            events |= Engine.WRITE
        if events != self._events:
            self._events = events
            Engine.instance().modify_channel(self)
    
    def _handle_read_event(self):
        """
        Handles a read event raised on the channel.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
    
    def _handle_write_event(self):
        """
        Handles a write event raised on the Channel.
        
        Not implemented in Channel.
        """
        raise NotImplementedError
