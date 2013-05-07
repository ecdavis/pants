from pants import Engine, Server, Stream

class BlockEcho(Stream):
    def on_connect(self):
        self.read_delimiter = 8

    def on_read(self, block):
        self.write(block + '\r\n')

server = Server(ConnectionClass=BlockEcho)
server.listen(4040)
Engine.instance().start()
