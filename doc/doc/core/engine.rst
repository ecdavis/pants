Engine
******

The :obj:`~pants.engine.Engine` is the core object of any Pants
application. It keeps track of every active :class:`~pants.channel.Channel`
and continuously checks them for new events, raising them when they occur.
The engine also provides timer functionality which allows functions to be
executed after some delay without blocking the process.

The engine can be accessed in one of two ways, by importing it directly
from the ``pants`` package::

    from pants import engine

Or by using the :meth:`~pants.engine.Engine.instance` method to retrieve
the singleton instance::

    from pants.engine import Engine
    
    Engine.instance()

These two methods are equivalent.

Applications
============

The engine can be used in two different ways. It can provide the main
event loop for your application, or it can be integrated into an
existing event loop (one run by a GUI framework, for instance).

Event Loop
----------

If you choose to use Pants' event loop, you will need to start the engine
with the :meth:`~pants.engine.Engine.start` method::

    engine.start()

This will cause the engine to start running until it is stopped either by
an uncaught :obj:`Exception` or the :meth:`~pants.engine.Engine.stop`
method::

    engine.stop()

The :meth:`~pants.engine.Engine.start` method blocks the process until
:meth:`~pants.engine.Engine.stop` is called, so be sure to fully initialise
your application before you call it.

Integration
-----------

If you want to integrate Pants with an existing event loop, you will need
to call :meth:`~pants.engine.Engine.poll` on each iteration of that loop::

    while True:
        engine.poll(0.02)
        do_other_stuff()

Ideally, :meth:`~pants.engine.Engine.poll` should be called many times
each second to ensure that Pants is as fast as it can be.

Timers
======

There are four types of timers in Pants: callbacks, loops, deferreds and
cycles. Timers rely on the Pants event loop, and will not function properly
if the event loop is not running or :meth:`~pants.engine.Engine.poll` is
not being called regularly.

When a callback is scheduled, it will be executed on the next iteration
of the event loop::

    engine.callback(my_func)

When a loop is scheduled, it will be executed on each iteration of the
event loop::

    engine.loop(my_loop)

When a deferred is scheduled, it will be executed after the specified
delay::

    engine.defer(my_deferred, 10.0)

When a cycle is scheduled, it will be executed repeatedly after the
specified delay::

    engine.cycle(my_cycle, 10.0)

The :meth:`~pants.engine.Engine.callback`, :meth:`~pants.engine.Engine.loop`,
:meth:`~pants.engine.Engine.defer` and :meth:`~pants.engine.Engine.cycle`
methods all return a dummy object that can be used to cancel the scheduled
timer prematurely::

    cycle = engine.cycle(my_cycle, 10.0)
    cycle.cancel()

The timer methods can have any number of positional and keyword arguments
passed to them, and the arguments will be passed through to the given
function when it is executed.

API
===

.. autoclass:: pants.engine.Engine
   :members: instance, start, stop, poll, callback, loop, defer, cycle
