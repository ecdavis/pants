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
import socket

import pants.channel
from pants.channel import Channel
from pants.engine import Engine


###############################################################################
# Constants
###############################################################################

NO_ERROR = 0
AN_ERROR = 1
# This is an error that cannot possibly be raised by a socket. It can
# be used in tests to mock a socket.error that absolutely won't match
# a "real" error.
IMPOSSIBLE_ERROR = errno.ENOTTY

EXAMPLE_ADDRESS = ('example.com', 80)

EXAMPLE_STRING = "foobarbaz"
EXAMPLE_STRING_LENGTH = 9



###############################################################################
# Mock Objects
###############################################################################

class MockSocket(object):
    def __init__(self, err=NO_ERROR, exc=socket.error):
        self._socket = socket.socket()
        self._exc = exc
        self._err = err
        
        self.connect_ex_called = False
        self.connect_ex_addr = None
        
        self.listen_called = False
        self.listen_backlog = None
        
        self.close_called = False
        
        self.accept_called = False
        
        self.recv_called = False
        
        self.recvfrom_called = False
        
        self.send_called = False
        self.send_buffer = ""
        
        self.sendto_called = False
        self.sendto_addr = None
        
        self._initted = True
    
    def __getattr__(self, key):
        return getattr(self._socket, key)
    
    def __setattr__(self, key, value):
        if not hasattr(self, "_initted") or hasattr(self, key):
            return object.__setattr__(self, key, value)
        else:
            return setattr(self._socket, key, value)
    
    def _raise_exc(self):
        raise self._exc(self._err)
    
    def connect_ex(self, addr):
        self.connect_ex_called = True
        self.connect_ex_addr = addr
        
        if self._err == NO_ERROR:
            return 0
        else:
            self._raise_exc()
    
    def listen(self, backlog):
        self.listen_backlog = backlog
        
        if self._err != NO_ERROR:
            self._raise_exc()
    
    def close(self):
        self.close_called = True
        
        if self._err != NO_ERROR:
            self._raise_exc()
    
    def accept(self):
        self.accept_called = True
        
        if self._err == NO_ERROR:
            return None, EXAMPLE_ADDRESS
        else:
            self._raise_exc()
    
    def recv(self, recv_amount):
        self.recv_called = True
        
        if self._err == NO_ERROR:
            return EXAMPLE_STRING
        else:
            self._raise_exc()
    
    def recvfrom(self, recv_amount):
        self.recvfrom_called = True
        
        if self._err == NO_ERROR:
            return EXAMPLE_STRING, EXAMPLE_ADDRESS
        else:
            self._raise_exc()
    
    def send(self, data):
        self.send_called = True
        self.send_buffer += data
        
        if self._err == NO_ERROR:
            return len(data)
        else:
            self._raise_exc()
    
    def sendto(self, data, addr):
        self.sendto_called = True
        self.sendto_addr = addr
        self.send_buffer += data
        
        if self._err == NO_ERROR:
            return len(data)
        else:
            self._raise_exc()

class MockChannel(Channel):
    def __init__(self, **kwargs):
        Channel.__init__(self, **kwargs)
        
        self.close_called = False
        self.handle_read_event_called = False
        self.handle_write_event_called = False
    
    def close(self):    
        self.close_called = True
        
        self._socket = None
        self.fileno = None
    
    def closed(self):
        return False
    
    def _handle_read_event(self):
        self.handle_read_event_called = True
    
    def _handle_write_event(self):
        self.handle_write_event_called = True


###############################################################################
# __init__() Tests
###############################################################################

def test_init():
    chan = Channel()
    
    assert isinstance(chan._socket, socket.socket)
    assert chan._socket.family == socket.AF_INET
    assert chan._socket.type == socket.SOCK_STREAM

def test_init_with_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chan = Channel(socket=sock)
    
    assert chan._socket is sock

def test_init_with_type():
    chan = Channel(type=socket.SOCK_DGRAM)
    
    assert chan._socket.type == socket.SOCK_DGRAM

def test_init_with_socket_and_type():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chan = Channel(socket=sock, type=socket.SOCK_DGRAM)
    
    assert chan._socket is sock

def test_init_adds_channel_to_Engine():
    engn = Engine.instance()
    chan = Channel()
    
    assert chan.fileno in engn._channels
    assert engn._channels[chan.fileno] is chan


###############################################################################
# _handle_events() tests
###############################################################################

def test_handle_events_with_no_events():
    chan = MockChannel()
    
    chan._handle_events(Engine.NONE)
    
    assert not chan.handle_read_event_called
    assert not chan.handle_write_event_called
    assert not chan.close_called

def test_handle_events_with_read_event():
    chan = MockChannel()
    
    chan._handle_events(Engine.READ)
    
    assert chan.handle_read_event_called
    assert not chan.handle_write_event_called
    assert not chan.close_called

def test_handle_events_with_write_event():
    chan = MockChannel()
    
    chan._handle_events(Engine.WRITE)
    
    assert not chan.handle_read_event_called
    assert chan.handle_write_event_called
    assert not chan.close_called

def test_handle_events_with_error_event():
    chan = MockChannel()
    
    chan._handle_events(Engine.ERROR)
    
    assert not chan.handle_read_event_called
    assert not chan.handle_write_event_called
    assert chan.close_called

def test_handle_events_with_read_and_write_events():
    chan = MockChannel()
    
    chan._handle_events(Engine.READ | Engine.WRITE)
    
    assert chan.handle_read_event_called
    assert chan.handle_write_event_called
    assert not chan.close_called

def test_handle_events_with_read_and_error_events():
    chan = MockChannel()
    
    chan._handle_events(Engine.READ | Engine.ERROR)
    
    assert chan.handle_read_event_called
    assert not chan.handle_write_event_called
    assert chan.close_called

def test_handle_events_with_write_and_error_events():
    chan = MockChannel()
    
    chan._handle_events(Engine.WRITE | Engine.ERROR)
    
    assert not chan.handle_read_event_called
    assert chan.handle_write_event_called
    assert chan.close_called

def test_handle_events_with_read_write_and_error_events():
    chan = MockChannel()
    
    chan._handle_events(Engine.READ | Engine.WRITE | Engine.ERROR)
    
    assert chan.handle_read_event_called
    assert chan.handle_write_event_called
    assert chan.close_called

# TODO Improve coverage of final block in _handle_events()


###############################################################################
# _socket_set() tests
###############################################################################

def test_socket_set_with_default_socket():
    chan = MockChannel()
    chan.close()
    sock = socket.socket()
    sock.setblocking(True)
    
    chan._socket_set(sock)
    
    assert chan._socket is sock
    assert chan.fileno == sock.fileno()
    assert chan._socket.gettimeout() == 0, "Socket should be non-blocking."

def test_socket_set_when_channel_has_a_preexisting_socket():
    chan = MockChannel()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        chan._socket_set(sock)
        assert False, "RuntimeError should be raised."
    except RuntimeError:
        assert True

def test_socket_set_with_socket_with_unsupported_family():
    chan = MockChannel()
    chan.close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # A little trickery is required here to get around actual OS
    # constraints on socket families.
    old_supported_families = pants.channel.SUPPORTED_FAMILIES
    try:
        pants.channel.SUPPORTED_FAMILIES = ()
        try:
            chan._socket_set(sock)
            assert False, "ValueError should be raised."
        except ValueError:
            assert True
    finally:
        pants.channel.SUPPORTED_FAMILIES = old_supported_families

def test_socket_set_with_socket_with_unsupported_type():
    chan = MockChannel()
    chan.close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # A little trickery is required here to get around actual OS
    # constraints on socket types.
    old_supported_types = pants.channel.SUPPORTED_TYPES
    try:
        pants.channel.SUPPORTED_TYPES = ()
        try:
            chan._socket_set(sock)
            assert False, "ValueError should be raised."
        except ValueError:
            assert True
    finally:
        pants.channel.SUPPORTED_TYPES = old_supported_types


###############################################################################
# _socket_connect() tests
###############################################################################

def test_socket_connect():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_connect(EXAMPLE_ADDRESS)
    
    assert ret
    assert sock.connect_ex_addr == EXAMPLE_ADDRESS

def test_socket_connect_when_channel_is_already_connected():
    sock = MockSocket(errno.EISCONN)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_connect(EXAMPLE_ADDRESS)
    
    assert ret

def test_socket_connect_when_connection_is_already_in_progress():
    sock = MockSocket(errno.EINPROGRESS)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_connect(EXAMPLE_ADDRESS)
    
    assert not ret

def test_socket_connect_when_uncaught_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR)
    chan = MockChannel(socket=sock)
    
    try:
        chan._socket_connect(EXAMPLE_ADDRESS)
        assert False, "socket.error should be raised."
    except socket.error as e:
        assert e[0] == IMPOSSIBLE_ERROR


###############################################################################
# _socket_listen() tests
###############################################################################

def test_socket_listen():
    chan = MockChannel()
    
    chan._readable = True
    chan._socket_listen(1024)
    
    assert not chan._readable

# TODO Should we test the backlog adjustment here?


###############################################################################
# _socket_close() tests
###############################################################################

def test_socket_close():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    chan._socket_close()
    
    assert sock.close_called
    assert chan._socket is None
    assert chan.fileno is None

def test_socket_close_when_AttributeError_is_raised():
    sock = MockSocket(AN_ERROR, AttributeError)
    chan = MockChannel(socket=sock)
    
    chan._socket_close()
    
    assert sock.close_called
    assert chan._socket is None
    assert chan.fileno is None

def test_socket_close_when_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR, socket.error)
    chan = MockChannel(socket=sock)
    
    chan._socket_close()
    
    assert sock.close_called
    assert chan._socket is None
    assert chan.fileno is None

def test_socket_close_when_Exception_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR, Exception)
    chan = MockChannel(socket=sock)
    
    try:
        chan._socket_close()
        assert False, "Exception should be raised."
    except Exception:
        assert True
    
    assert sock.close_called
    assert chan._socket is None
    assert chan.fileno is None


###############################################################################
# _socket_accept() tests
###############################################################################

def test_socket_accept():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_accept()
    
    assert sock.accept_called
    assert ret == (None, EXAMPLE_ADDRESS)

def test_socket_accept_when_accept_blocks():
    sock = MockSocket(errno.EAGAIN)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_accept()
    
    assert sock.accept_called
    assert ret == (None, ())
    assert not chan._readable

def test_socket_accept_when_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR)
    chan = MockChannel(socket=sock)
    
    try:
        ret = chan._socket_accept()
        assert False, "socket.error should be raised."
    except socket.error as e:
        assert e[0] == IMPOSSIBLE_ERROR


###############################################################################
# _socket_recv() tests
###############################################################################

def test_socket_recv():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_recv()
    
    assert ret == EXAMPLE_STRING

# TODO Test None return value?

def test_socket_recv_when_recv_blocks():
    sock = MockSocket(errno.EAGAIN)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_recv()
    
    assert ret == ''
    assert not chan._readable

def test_socket_recv_when_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR)
    chan = MockChannel(socket=sock)
    
    try:
        chan._socket_recv()
        assert False, "socket.error should be raised."
    except socket.error as e:
        assert e[0] == IMPOSSIBLE_ERROR


###############################################################################
# _socket_recvfrom() tests
###############################################################################

def test_socket_recvfrom():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_recvfrom()
    
    assert ret == (EXAMPLE_STRING, EXAMPLE_ADDRESS)

# TODO Test None return value?

def test_socket_recvfrom_when_recvfrom_blocks():
    sock = MockSocket(errno.EAGAIN)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_recvfrom()
    
    assert ret == ('', None)
    assert not chan._readable

def test_socket_recvfrom_when_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR)
    chan = MockChannel(socket=sock)
    
    try:
        chan._socket_recvfrom()
        assert False, "socket.error should be raised."
    except socket.error as e:
        assert e[0] == IMPOSSIBLE_ERROR


###############################################################################
# _socket_send() tests
###############################################################################

def test_socket_send():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_send(EXAMPLE_STRING)
    
    assert ret == EXAMPLE_STRING_LENGTH
    assert sock.send_buffer == EXAMPLE_STRING

def test_socket_send_when_send_blocks():
    sock = MockSocket(errno.EAGAIN)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_send(EXAMPLE_STRING)
    
    assert ret == 0
    assert not chan._writable

def test_socket_send_when_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR)
    chan = MockChannel(socket=sock)
    
    try:
        chan._socket_send(EXAMPLE_STRING)
        assert False, "socket.error should be raised."
    except socket.error as e:
        assert e[0] == IMPOSSIBLE_ERROR


###############################################################################
# _socket_sendto() tests
###############################################################################

def test_socket_sendto():
    sock = MockSocket()
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_sendto(EXAMPLE_STRING, EXAMPLE_ADDRESS)
    
    assert ret == EXAMPLE_STRING_LENGTH
    assert sock.send_buffer == EXAMPLE_STRING
    assert sock.sendto_addr == EXAMPLE_ADDRESS

def test_socket_sendto_when_sendto_blocks():
    sock = MockSocket(errno.EAGAIN)
    chan = MockChannel(socket=sock)
    
    ret = chan._socket_sendto(EXAMPLE_STRING, EXAMPLE_ADDRESS)
    
    assert ret == 0
    assert not chan._writable

def test_socket_sendto_when_socket_error_is_raised():
    sock = MockSocket(IMPOSSIBLE_ERROR)
    chan = MockChannel(socket=sock)
    
    try:
        chan._socket_sendto(EXAMPLE_STRING, EXAMPLE_ADDRESS)
        assert False, "socket.error should be raised."
    except socket.error as e:
        assert e[0] == IMPOSSIBLE_ERROR
