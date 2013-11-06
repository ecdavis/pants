
import socket
import unittest

from mock import call, MagicMock

from pants.stream import Stream

class TestStream(unittest.TestCase):
    def test_stream_constructor_with_invalid_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertRaises(TypeError, Stream, socket=sock)
        sock.close()

    def test_stream_set_read_delimiter_invalid_value(self):
        # not a great test, given that the error needs to be raised
        # with any non-valid type, not just with a list
        stream = Stream()
        passed = False
        try:
            stream.read_delimiter = []
        except TypeError:
            passed = True
        self.assertTrue(passed)

    def test_stream_handle_read_event_processes_recv_buffer_before_closing(self):
        # to ensure we don't reintroduce issue #41
        stream = Stream()
        stream._socket_recv = MagicMock(return_value=None)

        manager = MagicMock()
        stream._process_recv_buffer = manager._process_recv_buffer
        stream.close = manager.close

        stream._handle_read_event()

        expected_calls = [call._process_recv_buffer(), call.close(flush=False)]
        self.assertTrue(manager.mock_calls == expected_calls)
