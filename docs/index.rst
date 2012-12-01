:notitle:
:nosidebar:

.. |nobr| raw:: html

    <nobr>

.. |cnobr| raw:: html

    </nobr>


.. container:: row col2

    .. container:: item

        .. rubric:: Simple

        Pants handles sockets, data buffering, address families, SSL, and all
        the other boring details for you behind the scenes, leaving you to
        get straight to |nobr|\ the important part: *writing your application*.
        |cnobr|


    .. container:: item

        .. rubric:: Lightweight

        Pants has a small memory footprint, letting you maintain thousands of
        connections with ease. A basic :class:`~pants.stream.Stream` instance
        takes less than two kilobytes of memory.


    .. container:: item clear

        .. rubric:: Fast

        Pants is quick. The built-in HTTP server is able to handle thousands of
        requests per second across hundreds of simultaneous connections. And it
        only gets faster when you run it with `PyPy <http://pypy.org/>`_.


    .. container:: item

        .. rubric:: Attractive

        Coding with Pants is easy. Each connection is represented by an
        instance of :class:`~pants.stream.Stream`, and you implement your
        logic by overriding :func:`~pants.stream.Stream.on_read` and other
        functions.


    .. container:: item clear

        .. rubric:: Python

        Pants runs on CPython 2.6 and 2.7, with plans to port the codebase to
        run on 3.x after the release of version 1.0. Pants also runs great on
        PyPy.


    .. container:: item

        .. rubric:: Open Source

        Pants has been made available under the `Apache License, Version 2.0
        <http://www.apache.org/licenses/LICENSE-2.0.html>`_, so feel free to
        use it in your projects -- even if they're commercial and closed
        source.


------------


.. container:: row col3

    .. container:: item

        .. rubric:: Download

        .. code-block:: none

            pip install pants

        (You can also get it from `GitHub <https://github.com/ecdavis/Pants>`_.)

    .. container:: item

        .. rubric:: Learn

        Read the :doc:`documentation <documentation>`, browse the
        :doc:`examples <examples/index>`, and visit the `IRC
        <http://webchat.freenode.net/?channels=pantsmud>`_ channel to take
        part in the community.

    .. container:: item

        .. rubric:: Contribute

        Pants is always improving and you can help. Fork us on `GitHub
        <https://github.com/ecdavis/Pants>`_ and go wild. Be sure to visit the
        IRC channel to discuss your ideas.


------------

.. container:: row col2

    .. container:: item

        Here's an example of a simple echo server in Pants::

            from pants import Stream, Server, engine

            class Echo(Stream):
                def on_read(self, data):
                    self.write(data)

            if __name__ == '__main__':
                Server(Echo).listen(4040)
                engine.start()

    .. container:: item

        ... and here's a rather fast web server::

            from pants import engine
            from pants.http import HTTPServer
            from pants.web import Application

            app = Application()

            @app.route('/')
            def hello(request):
                return "Hello World!"

            if __name__ == '__main__':
                HTTPServer(app).listen()
                engine.start()
