from pants import Engine, Server, Stream

class Echo(Stream):
    def on_read(self, data):
        self.write(data)

Server(Echo).listen(4040)
Engine.instance().start()
