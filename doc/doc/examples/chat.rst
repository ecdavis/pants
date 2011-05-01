Chat
****

A chat server that relays messages between all connected users is relatively simple::

    from pants import Connection, engine, Server
    
    class ChatConnection(Connection):
        def __init__(self, *args):
            Connection.__init__(self, *args)
            
            self.inbuf = ""
        
        def handle_connect(self):
            self.server.message("%d joined the room." % self.fileno)
        
        def handle_read(self, data):
            self.inbuf += data
            
            while '\r\n' in self.inbuf:
                line, self.inbuf = self.inbuf.split('\r\n', 1)
                self.server.message("%d: %s" % (self.fileno, line))
        
        def handle_close(self):
            del self.server.channels[self.fileno]
            self.server.message("%d left the room." % self.fileno)
    
    class ChatServer(Server):
        ConnectionClass = ChatConnection
        
        def message(self, message):
            for conn in self.channels.itervalues():
                conn.send(message + '\r\n')
    
    ChatServer().listen(4000)
    engine.start()
