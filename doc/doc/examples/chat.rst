Chat
****

A basic chat server that relays messages between all connected users is
relatively simple::

    from pants import Connection, engine, Server
    
    class ChatConnection(Connection):
        def on_connect(self):
            self.read_delimiter = "\r\n"
            
            self.server.message("%d joined the room." % self.fileno)
        
        def on_read(self, data):
            self.server.message("%d: %s" % (self.fileno, data))
        
        def on_close(self):
            self.server.message("%d left the room." % self.fileno)
    
    class ChatServer(Server):
        ConnectionClass = ChatConnection
        
        def message(self, message):
            for conn in self.channels.itervalues():
                conn.write(message + "\r\n")
    
    ChatServer().listen(4000)
    engine.start()
