from pants import engine, Server, Stream

class Echo(Stream):
    def on_read(self, data):
        self.write(data)

Server(Echo).listen(4040)
engine.start()
