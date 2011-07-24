Timers
******
It is often necessary to delay function calls for some amount of time. Pants
makes this possible through the use of four types of **timers** - Callbacks,
Loops, Deferreds and Cycles.

**Note:** The engine must be running (``engine.start()`` must be called)
before timers will function properly.

Callbacks
=========
A callback is a function that is executed at the beginning of the next
iteration of the engine's main loop. A callback can be created using the
``pants.callback()`` function::

    from pants import callback
    
    def foo():
        pass
    
    callback(foo)

Loop
====
A loop is a function that is executed at the beginning of every iteration of
the engine's main loop until it is cancelled. A loop can be created using the
``pants.loop()`` function::

    from pants import loop
    
    loop(foo)

Deferreds
=========
A deferred is a function that is executed after a certain amount of time has
passed. A deferred can be created using the ``pants.defer()`'' function::

    from pants import defer
    
    defer(foo, 10.0)

In the above example, the ``foo()`` function will be executed after 10 seconds.

Cycles
======
A cycle is a function that is executed at regular intervals. A cycle can be
created using the ``pants.cycle()`` function::

    from pants import cycle
    
    cycle(foo, 10.0)

In the above example, the ``foo()`` function will be executed every 10
seconds.

Passing Arguments to Timers
===========================
Positional and/or keyword arguments can be passed to the three timer functions.
These arguments will be passed to the delayed function when it is called::

    def foo(*args, **kwargs):
        pass
    
    callback(foo, 1, 2, 3, bar="baz")

**Note:** Any references passed to ``pants.callback()``, ``pants.defer()``
or ``pants.cycle()`` will be stored until the timer is either executed or
cancelled (see below).

Cancelling Timers
=================
The ``pants.callback()``, ``pants.loop()``, ``pants.defer()`` and ``pants.cycle()``
functions all return a simple object with a ``cancel()`` method. Calling this
method will prevent the timer from being executed::

    c = callback(foo)
    c.cancel()

Once cancelled, a timer cannot be restarted - a new timer must be created to
replace it.
