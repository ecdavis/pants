[Pants](http://pantsweb.org/)
=============================
Pants is a lightweight framework for writing asynchronous network applications
in Python. Pants is simple, fast and very good-looking.

Pants is available under the [Apache License, Version 2.0]
(http://www.apache.org/licenses/LICENSE-2.0.html)

Install
=======
Pants can be installed using [pip](http://http://pypi.python.org/pypi/pip):

    pip install pants

You can also grab the latest code from the [git](http://git-scm.com/)
repository:

    git clone git://github.com/ecdavis/pants

Pants requires [Python 2.6+](http://python.org/) - Python 3 is not yet
supported.

Community
=========
Pants has a small but active community of developers who congregate in the IRC
channel [#pantsmud](http://webchat.freenode.net/?channels=pantsmud) on
irc.freenode.net.

Examples
========
Here's an absurdly simple example - Hello World:

```python
from pants import Connection, engine, Server

class Hello(Connection):
    def on_connect(self):
        self.write("Hello, World!\r\n")
        self.close()

Server(Hello).listen()
engine.start()
```

Want a stupidly fast web server? Got you covered:

```python
from pants import engine
from pants.web import Application, HTTPServer

app = Application()

@app.route('/')
def hello():
    return "Hello, World!"

HTTPServer(app).listen()
engine.start()
```
