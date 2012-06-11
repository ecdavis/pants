:notitle:
:nosidebar:

.. container:: row col2

    .. container:: item

        .. image:: /_static/icon1.jpg
            :alt: Simple

        .. rubric:: Simple

        Pants handles your sockets for you, and lets you get straight to
        implementing your application logic with simple subclasses of the
        :doc:`basic Pants classes <core/basic>`.

    .. container:: item

        .. image:: /_static/icon2.jpg
            :alt: Lightweight

        .. rubric:: Lightweight

        Pants is free of bloat and has a low memory footprint.

    .. container:: item clear

        .. image:: /_static/icon3.jpg
            :alt: Fast

        .. rubric:: Fast

        Pants has been written for speed from day one, and
        :doc:`it shows <benchmarks>`, with HTTP performance that blows past
        Tornado and twisted.

    .. container:: item

        .. image:: /_static/icon4.jpg
            :alt: Attractive

        .. rubric:: Attractive

        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus
        vulputate laoreet scelerisque. Phasellus velit quam, iaculis ac pulvinar
        feugiat, malesuada non arcu. Aliquam erat volutpat.

    .. container:: item clear

        .. image:: /_static/icon5.jpg
            :alt: Python

        .. rubric:: Python

        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus
        vulputate laoreet scelerisque. Phasellus velit quam, iaculis ac pulvinar
        feugiat, malesuada non arcu. Aliquam erat volutpat.

    .. container:: item

        .. image:: /_static/icon6.jpg
            :alt: Open Source

        .. rubric:: Open Source

        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus
        vulputate laoreet scelerisque. Phasellus velit quam, iaculis ac pulvinar
        feugiat, malesuada non arcu. Aliquam erat volutpat.


------------


.. container:: row col3

    .. container:: item

        .. rubric:: Download

        Do it now.

    .. container:: item

        .. rubric:: Learn

        Do this too.

    .. container:: item

        .. rubric:: Contribute

        If you want, you can even do this.


------------

.. container:: row col2

    .. container:: item

        Here's an example of a simple echo server in Pants::

            from pants import Connection, Server, engine

            class Echo(Connection):
                def on_read(self, data):
                    self.write(data)

            if __name__ == '__main__':
                Server(Echo).listen()
                engine.start()

    .. container:: item

        ... and here's a rather fast web server::

            from pants import engine
            from pants.http import HTTPServer
            from pants.web import Application

            app = Application()

            @app.route('/')
            def hello():
                return "Hello World!"

            if __name__ == '__main__':
                HTTPServer(app).listen()
                engine.start()
