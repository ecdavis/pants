Using the engine
****************

Applications
------------

The :obj:`~pants.engine.Engine` can be used in two different ways. It
can provide the main event loop for your application, or it can be
integrated into an existing event loop (one run by a GUI framework, for
instance).

If you choose to use Pants' event loop, you will need to start the
:obj:`~pants.engine.Engine` with the :meth:`~pants.engine.Engine.start`
method. This will cause the :obj:`~pants.engine.Engine` to call
:meth:`~pants.engine.Engine.poll` continuously until it is stopped
either by an uncaught :exc:`Exception` or the
:meth:`~pants.engine.Engine.stop` method. The :meth:`~pants.engine.Engine.start` method blocks the process until
:meth:`~pants.engine.Engine.stop` is called, so be sure to fully initialise
your application before you call it.

If you want to integrate Pants with an existing event loop, you will need
to call :meth:`~pants.engine.Engine.poll` on each iteration of that loop.
Ideally, :meth:`~pants.engine.Engine.poll` should be called many times
each second to ensure that Pants is as fast as it can be.

Accessing the Engine
--------------------

The :obj:`~pants.engine.Engine` can be accessed in one of two ways, by
importing it directly from the ``pants`` package::

    from pants import engine

Or by using the :meth:`~pants.engine.Engine.instance` classmethod::

    from pants.engine import Engine

    Engine.instance()

These two methods are equivalent.
