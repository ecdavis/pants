Using the Engine
****************

Pants applications are powered by a singleton object called the **engine**.


Accessing the Engine
====================

The :obj:`~pants.engine.Engine` can be accessed in one of two ways, by
importing it directly from the ``pants`` package::

    from pants import engine

Or by using the :meth:`~pants.engine.Engine.instance` classmethod::

    from pants.engine import Engine

    engine = Engine.instance()

These two methods are equivalent.


Starting and Stopping
=====================

The engine is started with a call to
:meth:`Engine.start() <pants.engine.Engine.start>`::

    engine.start()

This method will enter a loop which will continuously call
:meth:`Engine.poll() <pants.engine.Engine.poll>` until the engine is stopped
with a call to :meth:`Engine.stop() <pants.engine.Engine.stop>`::

    engine.stop()

After the engine is started, it blocks the process until it is stopped. This
means that you must completely initialise your application before starting the
engine in order for it to work as expected.


Integration
===========

It is possible to integrate Pants into an existing main loop, such as a GUI
framework's event loop.

If you need to integrate with an existing loop, you should not use the
:meth:`Engine.start() <pants.engine.Engine.start>` and
:meth:`Engine.stop() <pants.engine.Engine.stop>` methods, but instead call
:meth:`Engine.poll() <pants.engine.Engine.poll>` on each iteration of your
loop. Ideally, :meth:`~pants.engine.Engine.poll` should be called many times
each second to ensure that Pants is as fast as it can be.


Timers
======

The engine is responsible for scheduling timers.

**Further information:** :doc:`using_timers`
