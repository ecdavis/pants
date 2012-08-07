Basic
*****


Hello, World!
=============

The ultra-simple Hello World server using Pants::

    from pants import *

    class HelloWorld(Connection):
        def on_connect(self):
            self.write("Hello, World!")
            self.close(True)

    Server(HelloWorld).listen(4040)
    engine.start()

The server listens for connections on port 4040. When a connection is
established, it writes "Hello, World!" to the socket and then closes the
connection.


Message-Oriented
================

A simple server that understands a basic, variable-length message protocol::

    import struct

    from pants import *

    class MessageOriented(Connection):
        def on_connect(self):
            self.read_delimiter = 2
            self.on_read = self.on_read_header

        def on_read_header(self, data):
            message_length, = struct.unpack("!H", data)

            self.read_delimiter = message_length
            self.on_read = self.on_read_message

        def on_read_message(self, message):
            print message

            self.read_delimiter = 2
            self.on_read = self.on_read_header

    Server(MessageOriented).listen(4040)
    engine.start()

This example reads messages preceded by an unsigned short containing the
message length. As you can see, it is possible to be fairly inventive when
combining the read delimiter with the ability to replace callback methods at
runtime.

