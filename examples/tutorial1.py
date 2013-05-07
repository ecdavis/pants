from pants import Engine, Server, Stream

class Echo(Stream):
    def on_read(self, data):
        self.write(data)

server = Server(ConnectionClass=Echo)
server.listen(4040)
Engine.instance().start()
