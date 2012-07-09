
import socket
import unittest

from pants.stream import Stream

class TestStream(unittest.TestCase):
    def test_stream_constructor_with_invalid_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertRaises(TypeError, Stream, socket=sock)
    
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
