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

import socket

from pants.channel import Channel
from pants.engine import Engine


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Datagram Class
###############################################################################

class Datagram(Channel):
    def __init__(self, **kwargs):
        if "type" not in kwargs:
            kwargs["type"] = socket.SOCK_DGRAM
        
        Channel.__init__(self, **kwargs)
        
        # I/O attributes.
        self._recv_buffer = {}
        self._send_buffer = []
        
        # Internal state.
        self._listening = False
    
    ##### Status Methods ######################################################
    
    def active(self):
        """
        """
        return self._socket is not None and (self._listening or
                self._send_buffer)
    
    def listening(self):
        """
        """
        return self._listening
    
    ##### Control Methods #####################################################
    
    def listen(self, port=8080, host='', backlog=1024):  
        """
        """  
        if self._listening:
            # TODO Should this raise an exception?
            log.warning("listen() called on listening %s #%d."
                    % (self.__class__.__name__, self.fileno))
            return self
        
        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError, e:
            pass
        
        try:
            self._socket_bind((host, port))
        except socket.error, err:    
            # TODO Raise exception here?
            log.exception("Exception raised in listen() on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            # TODO Close this Stream here?
            self.close()
            return self
        
        self._update_addr()
        self._listening = True
        
        return self
    
    def close(self):
        """
        """
        if self._socket is None:
            return
        
        Engine.instance().remove_channel(self)
        self._socket_close()
        self._listening = False
        self._recv_buffer = {}
        self.read_delimiter = None
        self._send_buffer = []
        self._update_addr()
        self._safely_call(self.on_close)
    
    def end(self):
        """
        """    
        if self._socket is None:
            return
        
        if not self._send_buffer:
            self.close()
        else:
            self.on_write = self.close
    
    ##### I/O Methods #########################################################
    
    def write(self, data, addr=None, buffer_data=False):
        """
        """
        self._send(data, addr, buffer_data)
    
    def _send(self, data, addr, buffer_data):
        """
        """
        if self._socket is None:
            log.warning("Attempted to write to closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return
        
        if addr is None:
            addr = self.remote_addr
            if addr[0] is None:
                log.warning("Attempted to write to %s #%d with no remote address." %
                        (self.__class__.__name__, self.fileno))
                return
        
        if buffer_data or self._send_buffer:
            self._send_buffer.append((data, addr))
            # NOTE _wait_for_write() is normally called by _socket_send()
            #      when no more data can be sent. We call it here because
            #      _socket_send() will not be called.
            self._wait_for_write()
            return
        
        try:
            bytes_sent = self._socket_sendto(data, addr)
        except socket.error, err:
            # TODO Raise an exception here?
            log.exception("Exception raised in write() on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            # TODO Close this Datagram here?
            self.close()
            return
        
        if len(data[bytes_sent:]) > 0:
            self._send_buffer.append((data[bytes_sent:], addr))
        else:
            self._safely_call(self.on_write)
    
    ##### Private Methods #####################################################
    
    def _update_addr(self):
        """
        """
        if self._listening:
            self.local_addr = self._socket.getsockname()
        else:
            self.local_addr = (None, None)
    
    ##### Internal Event Handler Methods ######################################
    
    def _handle_read_event(self):
        """
        """
        if self._socket is None:
            log.warning("Received read event for closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return
        
        if not self._listening:
            # TODO ???
            log.warning("Received read event for non-listening %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return
        
        while True:
            try:
                data, addr = self._socket_recvfrom()
            except socket.error, err:
                log.exception("Exception raised by recvfrom() on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                # TODO Close this Datagram here?
                self.close()
                return
            
            if not data:
                break
            
            self._recv_buffer[addr] = self._recv_buffer.get(addr, '') + data
        
        self._process_recv_buffer()
    
    def _handle_write_event(self):
        """
        """
        if self._socket is None:
            log.warning("Received write event for closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return
        
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
    
    ##### Internal Processing Methods #########################################
    
    def _process_recv_buffer(self):
        for addr in self._recv_buffer:
            buf = self._recv_buffer[addr]
            self.remote_addr = addr
            
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
                    buf = buf[mark+len(delimiter):]
                    self._safely_call(self.on_read, data)
                
                else:
                    log.warning("Invalid read_delimiter on %s #%d." %
                            (self.__class__.__name__, self.fileno))
                    break
                
                if not self.active():
                    break
            
            self.remote_addr = (None, None)
            
            if buf:
                self._recv_buffer[addr] = buf
            else:
                del self._recv_buffer[addr]
            
            if not self.active():
                break


###############################################################################
# sendto Function
###############################################################################

_datagram = None

def sendto(data, host, port):
    """
    """
    global _datagram
    
    if _datagram is None:
        _datagram = Datagram()
    
    _datagram.write(data, (host, port))
