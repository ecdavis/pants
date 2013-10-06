###############################################################################
#
# Copyright 2012 Pants Developers (see AUTHORS.txt)
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

import errno
import socket
import sys
import unittest

from mock import MagicMock

from pants.engine import Engine
from pants._channel import _Channel, HAS_UNIX, HAS_IPV6, InvalidAddressFormatError
import pants._channel

class TestChannelConstructorArguments(unittest.TestCase):
    def test_channel_constructor_no_args(self):
        channel = _Channel()
        self.assertTrue(channel.engine is Engine.instance())
        self.assertTrue(channel._socket is None)

    def test_channel_constructor_socket_arg(self):
        sock = socket.socket()
        channel = _Channel(socket=sock)
        self.assertTrue(channel._socket is sock)

    def test_channel_constructor_engine_arg(self):
        engine = Engine()
        channel = _Channel(engine=engine)
        self.assertTrue(channel.engine is engine)

class TestChannelEngineInteraction(unittest.TestCase):
    def test_channel_gets_added_to_engine(self):
        engine = Engine()
        engine.add_channel = MagicMock()
        channel = _Channel(socket=socket.socket(), engine=engine)
        engine.add_channel.assert_called_once_with(channel)
        channel.close()

    def test_channel_gets_removed_from_engine(self):
        engine = Engine()
        engine.remove_channel = MagicMock()
        channel = _Channel(socket=socket.socket(), engine=engine)
        channel.close()
        engine.remove_channel.assert_called_once_with(channel)

class TestChannelFileno(unittest.TestCase):
    def test_channel_fileno_with_no_socket(self):
        channel = _Channel()
        self.assertTrue(channel.fileno is None)

    def test_channel_fileno_with_socket(self):
        sock = socket.socket()
        channel = _Channel(socket=sock)
        self.assertTrue(channel.fileno == sock.fileno())

class TestChannelClose(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()

    def test_channel_close_does_not_raise_an_exception_with_no_socket(self):
        try:
            self.channel.close()
        except TypeError:
            self.fail("Attempted to remove a socketless channel from the engine.")

    def test_channel_close_does_not_call_on_close(self):
        self.channel.on_close = MagicMock()
        self.channel.close()
        self.assertRaises(AssertionError, self.channel.on_close.assert_any_call)

class TestChannelSocketSet(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()

    def test_socket_set_with_acceptable_socket(self):
        sock = MagicMock()
        sock.family = socket.AF_INET
        sock.type = socket.SOCK_STREAM
        sock.setblocking = MagicMock()
        self.channel._socket_set(sock)
        self.assertTrue(self.channel._socket is sock)
        sock.setblocking.assert_called_once_with(False)

    def test_socket_set_with_preexisting_socket(self):
        self.channel._socket = MagicMock()
        self.assertRaises(RuntimeError, self.channel._socket_set, None)

    def test_socket_set_with_unsupported_family(self):
        sock = MagicMock()
        sock.family = 9001
        self.assertRaises(ValueError, self.channel._socket_set, sock)

    def test_socket_set_with_unsupported_type(self):
        sock = MagicMock()
        sock.family = socket.AF_INET
        sock.type = 9001
        self.assertRaises(ValueError, self.channel._socket_set, sock)

class TestChannelSocketConnect(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_connect_ex_returns_success(self):
        self.sock.connect_ex = MagicMock(return_value=0)
        self.assertTrue(self.channel._socket_connect(None))

    def test_connect_ex_returns_EISCONN(self):
        self.sock.connect_ex = MagicMock(return_value=errno.EISCONN)
        self.assertTrue(self.channel._socket_connect(None))

    def test_connect_ex_returns_EAGAIN(self):
        self.sock.connect_ex = MagicMock(return_value=errno.EAGAIN)
        self.assertFalse(self.channel._socket_connect(None))

    def test_connect_ex_returns_EWOULDBLOCK(self):
        self.sock.connect_ex = MagicMock(return_value=errno.EWOULDBLOCK)
        self.assertFalse(self.channel._socket_connect(None))

    def test_connect_ex_returns_EINPROGRESS(self):
        self.sock.connect_ex = MagicMock(return_value=errno.EINPROGRESS)
        self.assertFalse(self.channel._socket_connect(None))

    def test_connect_ex_returns_EALREADY(self):
        self.sock.connect_ex = MagicMock(return_value=errno.EALREADY)
        self.assertFalse(self.channel._socket_connect(None))

    def test_connect_ex_returns_unknown(self):
        self.sock.connect_ex = MagicMock(return_value=-1)
        self.assertRaises(socket.error, self.channel._socket_connect, None)

    def test_connect_ex_raises_unknown(self):
        self.sock.connect_ex = MagicMock(side_effect=Exception)
        self.assertRaises(Exception, self.channel._socket_connect, None)

    def test_reraises_unknown_socket_error(self):
        self.sock.connect_ex = MagicMock(side_effect=socket.error(-1))
        self.assertRaises(socket.error, self.channel._socket_connect, None)

class TestChannelSocketBind(unittest.TestCase):
    def test_bind_is_called(self):
        channel = _Channel()
        channel._socket = MagicMock()
        channel._socket.bind = MagicMock()
        channel._socket_bind(None)
        channel._socket.bind.assert_called_once_with(None)

class TestChannelSocketListen(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.sock.listen = MagicMock()
        self.channel._socket = self.sock

    def test_listen_is_called(self):
        self.channel._socket_listen(1)
        self.sock.listen.assert_called_once_with(1)

    @unittest.skipUnless(sys.platform.startswith("win"), "Windows-specific functionality.")
    def test_listen_backlog_is_corrected_on_windows(self):
        self.channel._socket_listen(socket.SOMAXCONN+1)
        self.sock.listen.assert_called_once_with(socket.SOMAXCONN)
    
    @unittest.skipIf(sys.platform.startswith("win"), "Non-Windows-specific functionality.")
    def test_listen_backlog_is_not_corrected_on_other_platforms(self):
        self.channel._socket_listen(socket.SOMAXCONN+1)
        self.sock.listen.assert_called_once_with(socket.SOMAXCONN+1)

class TestChannelSocketClose(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_socket_close(self):
        self.channel._socket_close()
        self.assertTrue(self.channel._socket is None)
        self.assertTrue(self.channel._closed)

    def test_shutdown_is_called(self):
        shutdown = MagicMock()
        self.sock.shutdown = shutdown
        self.channel._socket_close()
        shutdown.assert_called_once_with(socket.SHUT_RDWR)

    def test_close_is_called(self):
        close = MagicMock()
        self.sock.close = close
        self.channel._socket_close()
        close.assert_called_once_with()

    def test_socket_error_is_raised(self):
        socket_error_raiser = MagicMock(side_effect=socket.error)
        self.sock.shutdown = socket_error_raiser
        try:
            self.channel._socket_close()
        except socket.error:
            self.fail("socket.error was not caught.")

class TestChannelSocketAccept(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_socket_accept(self):
        self.sock.accept = MagicMock(return_value=(1, 2, 3))
        self.assertEqual(self.channel._socket_accept(), (1, 2, 3))

    def test_accept_raises_EAGAIN(self):
        self.sock.accept = MagicMock(side_effect=socket.error(errno.EAGAIN))
        self.assertEqual(self.channel._socket_accept(), (None, None))

    def test_accept_raises_EWOULDBLOCK(self):
        self.sock.accept = MagicMock(side_effect=socket.error(errno.EWOULDBLOCK))
        self.assertEqual(self.channel._socket_accept(), (None, None))

    def test_accept_raises_unknown(self):
        self.sock.accept = MagicMock(side_effect=socket.error(-1))
        self.assertRaises(socket.error, self.channel._socket_accept)

class TestChannelSocketRecv(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_socket_recv(self):
        chunk = "foo"
        self.sock.recv = MagicMock(return_value=chunk)
        result = self.channel._socket_recv()
        self.assertEqual(result, chunk)
        self.sock.recv.assert_called_once_with(self.channel._recv_amount)

    def test_recv_returns_no_data(self):
        chunk = ""
        self.sock.recv = MagicMock(return_value=chunk)
        result = self.channel._socket_recv()
        self.assertEqual(result, None)

    def test_recv_raises_EAGAIN(self):
        self.sock.recv = MagicMock(side_effect=socket.error(errno.EAGAIN))
        result = self.channel._socket_recv()
        self.assertEqual(result, "")

    def test_recv_raises_EWOULDBLOCK(self):
        self.sock.recv = MagicMock(side_effect=socket.error(errno.EWOULDBLOCK))
        result = self.channel._socket_recv()
        self.assertEqual(result, "")

    def test_recv_raises_ECONNRESET(self):
        self.sock.recv = MagicMock(side_effect=socket.error(errno.ECONNRESET))
        result = self.channel._socket_recv()
        self.assertEqual(result, None)

    def test_recv_raises_unknown(self):
        self.sock.recv = MagicMock(side_effect=socket.error(-1))
        self.assertRaises(socket.error, self.channel._socket_recv)

class TestChannelSocketRecvFrom(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_socket_recvfrom(self):
        chunk = ("foo", None)
        self.sock.recvfrom = MagicMock(return_value=chunk)
        result = self.channel._socket_recvfrom()
        self.assertEqual(result, chunk)
        self.sock.recvfrom.assert_called_once_with(self.channel._recv_amount)

    def test_recvfrom_returns_no_data(self):
        chunk = ("", None)
        self.sock.recvfrom = MagicMock(return_value=chunk)
        result = self.channel._socket_recvfrom()
        self.assertEqual(result, (None, None))

    def test_recvfrom_raises_EAGAIN(self):
        self.sock.recvfrom = MagicMock(side_effect=socket.error(errno.EAGAIN))
        result = self.channel._socket_recvfrom()
        self.assertEqual(result, ("", None))

    def test_recvfrom_raises_EWOULDBLOCK(self):
        self.sock.recvfrom = MagicMock(side_effect=socket.error(errno.EWOULDBLOCK))
        result = self.channel._socket_recvfrom()
        self.assertEqual(result, ("", None))

    def test_recvfrom_raises_ECONNRESET(self):
        self.sock.recvfrom = MagicMock(side_effect=socket.error(errno.ECONNRESET))
        result = self.channel._socket_recvfrom()
        self.assertEqual(result, ("", None))

    def test_recvfrom_raises_unknown(self):
        self.sock.recvfrom = MagicMock(side_effect=socket.error(-1))
        self.assertRaises(socket.error, self.channel._socket_recvfrom)

class TestChannelSocketSend(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_socket_send(self):
        chunk = "foo"
        self.sock.send = MagicMock(return_value=len(chunk))
        self.assertEqual(self.channel._socket_send(chunk), len(chunk))
        self.sock.send.assert_called_once_with(chunk)

    def test_send_raises_EAGAIN(self):
        self.sock.send = MagicMock(side_effect=socket.error(errno.EAGAIN))
        self.channel._start_waiting_for_write_event = MagicMock()
        result = self.channel._socket_send(None)
        self.assertEqual(result, 0)
        self.channel._start_waiting_for_write_event.assert_called_once_with()

    def test_send_raises_EWOULDBLOCK(self):
        self.sock.send = MagicMock(side_effect=socket.error(errno.EWOULDBLOCK))
        self.channel._start_waiting_for_write_event = MagicMock()
        result = self.channel._socket_send(None)
        self.assertEqual(result, 0)
        self.channel._start_waiting_for_write_event.assert_called_once_with()

    def test_send_raises_EPIPE(self):
        self.sock.send = MagicMock(side_effect=Exception(errno.EPIPE))
        self.channel.close = MagicMock()
        result = self.channel._socket_send(None)
        self.assertEqual(result, 0)
        self.channel.close.assert_called_once_with(flush=False)

    def test_send_raises_unknown(self):
        self.sock.send = MagicMock(side_effect=Exception(-1))
        self.assertRaises(Exception, self.channel._socket_send)

class TestChannelSocketSendTo(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_socket_sendto(self):
        chunk = "foo"
        args = (chunk, None, None)
        self.sock.sendto = MagicMock(return_value=len(chunk))
        self.assertEqual(self.channel._socket_sendto(*args), len(chunk))
        self.sock.sendto.assert_called_once_with(*args)

    def test_sendto_raises_EAGAIN(self):
        self.sock.send = MagicMock(side_effect=socket.error(errno.EAGAIN))
        self.channel._start_waiting_for_write_event = MagicMock()
        result = self.channel._socket_send(None)
        self.assertEqual(result, 0)
        self.channel._start_waiting_for_write_event.assert_called_once_with()

    def test_sendto_raises_EWOULDBLOCK(self):
        self.sock.send = MagicMock(side_effect=socket.error(errno.EWOULDBLOCK))
        self.channel._start_waiting_for_write_event = MagicMock()
        result = self.channel._socket_send(None)
        self.assertEqual(result, 0)
        self.channel._start_waiting_for_write_event.assert_called_once_with()

    def test_sendto_raises_EPIPE(self):
        self.sock.send = MagicMock(side_effect=Exception(errno.EPIPE))
        self.channel.close = MagicMock()
        result = self.channel._socket_send(None)
        self.assertEqual(result, 0)
        self.channel.close.assert_called_once_with(flush=False)

    def test_sendto_raises_unknown(self):
        self.sock.send = MagicMock(side_effect=Exception(-1))
        self.assertRaises(Exception, self.channel._socket_send)

class TestChannelSocketSendfile(unittest.TestCase):
    def setUp(self):
        self._sendfile = pants._channel.sendfile
        self.channel = _Channel()

    def tearDown(self):
        pants._channel.sendfile = self._sendfile

    def test_socket_sendfile(self):
        chunk = "foo"
        args = (chunk, None, None, False)
        pants._channel.sendfile = MagicMock(return_value=len(chunk))
        self.assertEqual(self.channel._socket_sendfile(*args), len(chunk))
        pants._channel.sendfile.assert_called_once_with(chunk, self.channel, None, None, False)

    def test_sendfile_raises_EAGAIN(self):
        chunk = "foo"
        args = (chunk, None, None, False)
        err = socket.error(errno.EAGAIN)
        err.nbytes = 0 # See issue #43
        pants._channel.sendfile = MagicMock(side_effect=err)
        self.channel._start_waiting_for_write_event = MagicMock()
        result = self.channel._socket_sendfile(*args)
        self.assertEqual(result, 0)
        self.channel._start_waiting_for_write_event.assert_called_once_with()

    def test_sendfile_raises_EWOULDBLOCK(self):
        chunk = "foo"
        args = (chunk, None, None, False)
        err = socket.error(errno.EWOULDBLOCK)
        err.nbytes = 0 # See issue #43
        pants._channel.sendfile = MagicMock(side_effect=err)
        self.channel._start_waiting_for_write_event = MagicMock()
        result = self.channel._socket_sendfile(*args)
        self.assertEqual(result, 0)
        self.channel._start_waiting_for_write_event.assert_called_once_with()

    def test_sendfile_raises_EPIPE(self):
        chunk = "foo"
        args = (chunk, None, None, False)
        pants._channel.sendfile = MagicMock(side_effect=Exception(errno.EPIPE))
        self.channel.close = MagicMock()
        result = self.channel._socket_sendfile(*args)
        self.assertEqual(result, 0)
        self.channel.close.assert_called_once_with(flush=False)

    def test_sendfile_raises_unknown(self):
        pants._channel.sendfile = MagicMock(side_effect=Exception((-1,)))
        self.assertRaises(Exception, self.channel._socket_sendfile)

class TestChannelStartWaitingForWriteEvent(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()

    def test_when_write_needs_to_be_added(self):
        self.channel._events = Engine.NONE
        self.channel.engine.modify_channel = MagicMock()
        self.channel._start_waiting_for_write_event()
        self.assertEqual(self.channel._events, Engine.WRITE)
        self.channel.engine.modify_channel.assert_called_once_with(self.channel)

    def test_when_write_doesnt_need_to_be_added(self):
        self.channel._events = Engine.WRITE
        self.channel.engine.modify_channel = MagicMock()
        self.channel._start_waiting_for_write_event()
        self.assertEqual(self.channel._events, Engine.WRITE)
        self.assertRaises(AssertionError, self.channel.engine.modify_channel.assert_called_once_with)

class TestChannelStopWaitingForWriteEvent(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()

    def test_when_write_needs_to_be_removed(self):
        self.channel._events = Engine.WRITE
        self.channel.engine.modify_channel = MagicMock()
        self.channel._stop_waiting_for_write_event()
        self.assertEqual(self.channel._events, Engine.NONE)
        self.channel.engine.modify_channel.assert_called_once_with(self.channel)

    def test_when_write_doesnt_need_to_be_removed(self):
        self.channel._events = Engine.NONE
        self.channel.engine.modify_channel = MagicMock()
        self.channel._stop_waiting_for_write_event()
        self.assertEqual(self.channel._events, Engine.NONE)
        self.assertRaises(AssertionError, self.channel.engine.modify_channel.assert_called_once_with)

class TestChannelSafelyCall(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()

    def test_with_no_error(self):
        args = (1, 2, 3)
        kwargs = {"foo": "bar"}
        thing_to_call = MagicMock()
        self.channel._safely_call(thing_to_call, *args, **kwargs)
        thing_to_call.assert_called_once_with(*args, **kwargs)

    def test_with_an_error(self):
        args = (1, 2, 3)
        kwargs = {"foo": "bar"}
        thing_to_call = MagicMock(side_effect=Exception())
        self.channel._safely_call(thing_to_call, *args, **kwargs)
        thing_to_call.assert_called_once_with(*args, **kwargs)

class TestChannelGetSocketError(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.sock = MagicMock()
        self.channel._socket = self.sock

    def test_with_no_error(self):
        self.sock.getsockopt = MagicMock(return_value=0)
        err, errstr = self.channel._get_socket_error()
        self.sock.getsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_ERROR)
        self.assertEqual(err, 0)
        self.assertEqual(errstr, "")

    def test_with_an_error(self):
        self.sock.getsockopt = MagicMock(return_value=errno.EAGAIN)
        err, errstr = self.channel._get_socket_error()
        self.sock.getsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_ERROR)
        self.assertEqual(err, errno.EAGAIN)
        self.assertNotEqual(errstr, "")

class TestChannelFormatAddress(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()

    @unittest.skipUnless(HAS_UNIX, "Requires support for UNIX sockets.")
    def test_with_unix_address(self):
        path = "/home/example/socket"
        address, family, resolved = self.channel._format_address(path)
        self.assertEqual(address, path)
        self.assertEqual(family, socket.AF_UNIX)
        self.assertEqual(resolved, True)

    @unittest.skipIf(HAS_UNIX, "Requires no support for UNIX sockets.")
    def test_when_unix_address_is_invalid(self):
        path = "/home/example/socket"
        self.assertRaises(InvalidAddressFormatError, self.channel._format_address, path)

    def test_with_port_number(self):
        port = 8080
        address, family, resolved = self.channel._format_address(port)
        self.assertEqual(address, ("", port))
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(resolved, True)

    def test_inaddr_any(self):
        addr = ('', 80)
        address, family, resolved = self.channel._format_address(addr)
        self.assertEqual(address, addr)
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(resolved, True)

    def test_inaddr6_any(self):
        addr = ('', 80, 1, 2)
        address, family, resolved = self.channel._format_address(addr)
        self.assertEqual(address, addr)
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(resolved, True)

    def test_broadcast(self):
        addr = ('<broadcast>', 80)
        address, family, resolved = self.channel._format_address(addr)
        self.assertEqual(address, addr)
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(resolved, True)

    def test_broadcast6(self):
        addr = ('<broadcast>', 80, 1, 2)
        address, family, resolved = self.channel._format_address(addr)
        self.assertEqual(address, addr)
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(resolved, True)

    def test_with_invalid_ipv4_address(self):
        addr = (1, 2)
        self.assertRaises(InvalidAddressFormatError, self.channel._format_address, addr)

    def test_with_ipv4_address(self):
        addr = ('8.8.8.8', 2)
        address, family, resolved = self.channel._format_address(addr)
        self.assertEqual(address, ('8.8.8.8', 2))
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(resolved, True)

    @unittest.skipUnless(HAS_IPV6, "Requires support for IPv6 sockets.")
    def test_with_invalid_ipv6_address(self):
        addr = (1, 2, 3, 4)

    @unittest.skipUnless(HAS_IPV6, "Requires support for IPv6 sockets.")
    def test_with_ipv6_address(self):
        addr = ('::1', 2, 3, 4)
        address, family, resolved = self.channel._format_address(addr)
        self.assertEqual(address, addr)
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(resolved, True)

    @unittest.skipIf(HAS_IPV6, "Requires no support for IPv6 sockets.")
    def test_when_ipv6_address_is_invalid(self):
        addr = (1, 2, 3, 4)
        self.assertRaises(InvalidAddressFormatError, self.channel._format_address, addr)

    def test_with_invalid_addresses(self):
        self.assertRaises(InvalidAddressFormatError, self.channel._format_address, None)
        self.assertRaises(InvalidAddressFormatError, self.channel._format_address, (1, 2, 3))

@unittest.skip("Not yet implemented.")
class TestChannelResolveAddress(unittest.TestCase):
    @unittest.skipUnless(HAS_UNIX, "Requires support for UNIX sockets.")
    def test_resolve_unix_address(self):
        self.fail("Not yet implemented.")

    def test_resolve_ipv4_address(self):
        self.fail("Not yet implemented.")

    @unittest.skipUnless(HAS_IPV6, "Requires support for IPv6 sockets.")
    def test_resolve_inet6_address(self):
        self.fail("Not yet implemented.")

class TestChannelHandleEvents(unittest.TestCase):
    def setUp(self):
        self.channel = _Channel()
        self.channel._handle_read_event = MagicMock()
        self.channel._handle_write_event = MagicMock()
        self.channel._handle_error_event = MagicMock()
        self.channel._handle_hangup_event = MagicMock()

    def test_new_events_modify_engine(self):
        self.channel.engine.modify_channel = MagicMock()

        def add_events():
            self._events = Engine.ALL_EVENTS
        
        self.channel._handle_read_event = add_events
        self.channel._events = Engine.NONE
        self.channel._handle_events(Engine.READ)
        self.channel.engine.modify_channel.assert_called_once_with(self.channel)

    def test_when_channel_is_closed(self):
        self.channel._closed = True
        self.channel._handle_events(Engine.READ)
        self.assertRaises(AssertionError, self.channel._handle_read_event.assert_called_once_with)

    def test_with_no_events(self):
        self.channel._handle_events(Engine.NONE)
        self.assertRaises(AssertionError, self.channel._handle_read_event.assert_called_once_with)
        self.assertRaises(AssertionError, self.channel._handle_write_event.assert_called_once_with)
        self.assertRaises(AssertionError, self.channel._handle_error_event.assert_called_once_with)
        self.assertRaises(AssertionError, self.channel._handle_hangup_event.assert_called_once_with)

    def test_with_all_events(self):
        self.channel._handle_events(Engine.ALL_EVENTS)
        self.channel._handle_read_event.assert_called_once_with()
        self.channel._handle_write_event.assert_called_once_with()
        self.channel._handle_error_event.assert_called_once_with()
        self.channel._handle_hangup_event.assert_called_once_with()

    def test_with_abrupt_close(self):
        self.channel._handle_error_event = MagicMock(side_effect=self.channel.close)
        self.channel._handle_events(Engine.ALL_EVENTS)
        self.channel._handle_read_event.assert_called_once_with()
        self.channel._handle_write_event.assert_called_once_with()
        self.channel._handle_error_event.assert_called_once_with()
        self.assertRaises(AssertionError, self.channel._handle_hangup_event.assert_called_once_with)
