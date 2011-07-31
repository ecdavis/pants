[Pants](http://pantsweb.org/)
=============================
Pants is a lightweight framework for writing asynchronous network applications
in Python. It is a simple, efficient and versatile networking solution which
makes no assumptions about your use-case, provides no superfluous features and
is very good-looking.

Pants is available under the [Apache License, Version 2.0]
(http://www.apache.org/licenses/LICENSE-2.0.html)

Install
=======
Pants can be obtained in several ways. You can use [pip]
(http://http://pypi.python.org/pypi/pip):

    pip install pants

Or [setuptools](http://pypi.python.org/pypi/setuptools), if that's how you
roll:

    easy_install pants

Or for the bleeding edge version, you can clone the [git](http://git-scm.com/)
repository:

    git clone git://github.com/ecdavis/Pants pants

Pants requires [Python 2.6+](http://python.org/) - Python 3 is not yet
supported.

Community
=========
Pants has a small but active community of developers who congregate in the IRC
channel [#pantsmud](http://webchat.freenode.net/?channels=pantsmud) on
irc.freenode.net.

Hello World
===========
Here's an absurdly simple example - Hello World:

```python
from pants import Connection, engine, Server

class Hello(Connection):
    def on_connect(self):
        self.write("Hello, World!\r\n")
        self.close()

Server(Hello).listen(4000)
engine.start()
```

Want an absurdly fast web server? Got you covered:

```python
from pants.contrib.web import Application, HTTPServer
from pants import engine

app = Application()

@app.route('/')
def hello():
    return "Hello, World!"

HTTPServer(app).listen(80)
engine.start()
```