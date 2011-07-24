Overview
********

The Basic API
=============
The basic API can be accessed by simply importing the ``pants`` package::

    import pants

Or by importing only those elements of the API that you need in the current
module::

    from pants import engine

The Engine
==========
Pants relies on a core object called the **engine**. After your application is
fully initialised you must start the engine::

    from pants import engine
    
    engine.start()

It will continue to run until some part of your code forces it to stop::

    engine.stop()

The ``KeyboardInterrupt`` and ``SystemExit`` exceptions will cause the
engine to stop gracefully, and any other uncaught exception will also cause it
to stop with some attempt at grace.

Because Pants is an asynchronous framework, it is important that you avoid
writing blocking code wherever possible. Code that blocks for a lengthy period
of time will cause problems for networking, timers and any other code that
relies on Pants' asynchronous nature. ``engine.start()`` is the single
exception to this rule - it will block until the engine is stopped somehow::

    engine.start()
    print "foo"

In the above example, ``"foo"`` will not be displayed on the console until
the engine is stopped - usually when your application is shutting down. For
this reason, any initialisation required by your application must be performed
before ``engine.start()`` is called, or through the clever use of timers and
events.
