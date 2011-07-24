Echo
****

Implementing an echo server with Pants is very simple::

    from pants import Connection, engine, Server
    
    class Echo(Connection):
        def on_read(self, data):
            self.write(data)
    
    Server(Echo).listen(4000)
    engine.start()
