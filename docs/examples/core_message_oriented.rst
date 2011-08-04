Message-Oriented Connection
***************************


A simple server that understands a basic, variable-length message protocol::

    import struct
    
    from pants import *
    
    class MessageOriented(Connection):
        def on_connect(self):
            self.read_delimiter = 2
            self.on_read = self.on_read_header
        
        def on_read_header(self, data):
            message_length = struct.unpack("!H", data)
            
            self.read_delimiter = message_length
            self.on_read = self.on_read_message
        
        def on_read_message(self, message):
            print message
            
            self.read_delimiter = 2
            self.on_read = self.on_read_header
    
    Server(MessageOriented).listen(4000)
    engine.start()

This example reads messages preceded by an unsigned short containing the
message length. As you can see, it is possible to be fairly inventive when
combining the read delimiter with the ability to replace callback methods at
runtime.
