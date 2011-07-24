Engine
******

The :obj:`~pants.engine.Engine` is the core object of any Pants
application. It keeps track of every active :class:`~pants.channel.Channel`
and continuously checks them for new events, raising them when they occur.
The :obj:`~pants.engine.Engine` also provides timer functionality which
allows functions to be executed after some delay without blocking the
process.

The :obj:`~pants.engine.Engine` can be accessed in one of two ways, by
importing it directly from the ``pants`` package::

    from pants import engine

Or by using the :meth:`~pants.engine.Engine.instance` classmethod::

    from pants.engine import Engine
    
    Engine.instance()

These two methods are equivalent.

Applications
============

The :obj:`~pants.engine.Engine` can be used in two different ways. It
can provide the main event loop for your application, or it can be
integrated into an existing event loop (one run by a GUI framework, for
instance).

Event Loop
----------

If you choose to use Pants' event loop, you will need to start the
:obj:`~pants.engine.Engine` with the :meth:`~pants.engine.Engine.start`
method. This will cause the :obj:`~pants.engine.Engine` to call
:meth:`~pants.engine.Engine.poll` continuously until it is stopped
either by an uncaught :exc:`Exception` or the
:meth:`~pants.engine.Engine.stop` method.

The :meth:`~pants.engine.Engine.start` method blocks the process until
:meth:`~pants.engine.Engine.stop` is called, so be sure to fully initialise
your application before you call it.

Integration
-----------

If you want to integrate Pants with an existing event loop, you will need
to call :meth:`~pants.engine.Engine.poll` on each iteration of that loop.
Ideally, :meth:`~pants.engine.Engine.poll` should be called many times
each second to ensure that Pants is as fast as it can be.

Timers
======

Timers are function calls that are delayed until some point in the future.
There are four methods used for scheduling timers:
:meth:`~pants.engine.Engine.callback`, :meth:`~pants.engine.Engine.loop`,
:meth:`~pants.engine.Engine.defer` and :meth:`~pants.engine.Engine.cycle`.
These methods all return a callable that can be used to cancel the timer
at any time::

    cancel_callback = engine.callback(callback)
    cancel_callback()

The timer methods can be passed any number of positional and keyword
arguments, which will then be passed through to the given function when
it is executed.

API
===

.. autoclass:: pants.engine.Engine
   :members: instance, start, stop, poll, callback, loop, defer, cycle
