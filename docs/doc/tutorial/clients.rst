Clients
*******
An instance of the ``Client`` class represents a connection from the
application to a remote host. It's easy to create a client::

    from pants import Client
    
    client = Client().connect("example.com", 80)

The first argument there is the host and the second is the port.

Of course, in order to have a client that does something useful, it's necessary
to subclass ``Client``. Here's an example that closes immediately after it connects::

    class CloseClient(Client):
        def handle_connect(self):
            self.close()

Here's one that sends any data that it receives back to the server::

    class EchoClient(Client):
        def handle_read(self, data):
            self.send(data)

And here's one that opens a new client when it closes::

    class OpenClient(Client):
        def handle_close(self):
            OpenClient().connect(*self.remote_addr)

Silly stuff.
