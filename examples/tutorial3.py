from pants import Engine, Server, Stream

class EchoLineToAll(Stream):
    def on_connect(self):
        self.read_delimiter = '\r\n'
        self.server.write_to_all("Connected: %s\r\n" % self.remote_address[0])

    def on_read(self, line):
        self.server.write_to_all("%s: %s\r\n" % (self.remote_address[0], line))

    def on_close(self):
        self.server.write_to_all("Disconnected: %s\r\n" % self.remote_address[0])

class EchoLineToAllServer(Server):
    ConnectionClass = EchoLineToAll

    def write_to_all(self, data):
        for channel in self.channels.itervalues():
            if channel.connected:
                channel.write(data)

EchoLineToAllServer().listen(4040)
Engine.instance().start()
