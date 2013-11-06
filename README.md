[Pants](http://pantspowered.org/)
=================================
Pants is a lightweight framework for writing asynchronous network applications
in Python. Pants is simple, fast and elegant.

Pants is available under the [Apache License, Version 2.0]
(http://www.apache.org/licenses/LICENSE-2.0.html)

Docs
====
Check out the documentation at [pantspowered.org](http://pantspowered.org/)

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
channel [#pantspowered](http://webchat.freenode.net/?channels=pantspowered) on
irc.freenode.net.

Examples
========
Here's an absurdly simply example - an echo server:
```python
from pants import Engine, Server, Stream

class Echo(Stream):
    def on_read(self, data):
        self.write(data)

Server(Echo).listen(4040)
Engine.instance().start()
```

Want a stupidly fast web server? Got you covered:

```python
from pants.web import Application

app = Application()

@app.route('/')
def hello(request):
    return "Hello, World!"

app.run()
```
