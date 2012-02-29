Using Timers
************

It is often necessary to delay function calls for some amount of time. Pants
makes this possible through the use of four types of timers - **callbacks**,
**loops**, **deferreds** and **cycles**. Timers can be passed any number of
positional and keyword arguments, which are then passed through to the given
function when it is executed.


Creating Timers
===============

Timers are created by using one of four methods, depending on which type of
timer you are looking to create. The methods are:
:meth:`Engine.callback() <pants.engine.Engine.callback>`,
:meth:`Engine.loop() <pants.engine.Engine.loop>`,
:meth:`Engine.defer() <pants.engine.Engine.defer>` and
:meth:`Engine.cycle() <pants.engine.Engine.cycle>`.

Each of these methods is passed a callable to execute as well as some number
of positional and keyword arguments.
:meth:`Engine.defer() <pants.engine.Engine.defer>` and
:meth:`Engine.cycle() <pants.engine.Engine.cycle>` also take a number
specifying the delay, in seconds, after which they should be executed.

::

    engine.cycle(10.0, my_function, foo, bar=baz)

The above line of code will create a cycle, causing the :func:`my_function`
function to be executed every 10.0 seconds - :func:`my_function` will be
passed the value of ``foo`` as a positional argument and the value of ``baz``
as an argument with the keyword ``bar``.

Any object references passed to a timer method will be retained in memory
until the timer is executed or cancelled. Be aware of this when writing
code, as it may well cause unexpected behaviour if you fail to take these
references into account.

Timers rely on the :obj:`~pants.engine.Engine` for scheduling and execution.
For best results, you should either schedule timers while the engine is
running or start the engine immediately after scheduling your timers.


Cancelling Timers
=================

The four timer methods all return a callable object which can be used to
cancel the execution of the timer.

::

    cancel_cycle = engine.cycle(10.0, my_function, foo, bar=baz)
    cancel_cycle()

As above, this code creates a cycle which will cause the :func:`my_function`
function to be executed every 10.0 seconds. It then immediately cancels that
cycle by calling the object returned by
:meth:`Engine.cycle() <pants.engine.Engine.cycle>`. For obvious reasons, the
timer must actually be scheduled before it can be cancelled, so calling the
return object of a timer that has already run its course will have no effect.


Callbacks
=========

A callback is a function that is executed at the beginning of the next call to
:meth:`Engine.poll <pants.engine.Engine.poll>`. Callbacks are created by using
the :meth:`Engine.callback() <pants.engine.Engine.callback>` method::

    cancel_callback = engine.callback(my_function, foo, bar=baz)

In the above example, :func:`my_function` will be executed the next time
:meth:`Engine.poll <pants.engine.Engine.poll>` is called. That is, on the
next iteration of the main loop.


Loops
=====

A loop is a function that is executed at the beginning of every call to
:meth:`Engine.poll <pants.engine.Engine.poll>` after it is scheduled. Loops
are created by using the :meth:`Engine.loop() <pants.engine.Engine.loop>`
method::

    cancel_loop = engine.loop(my_function, foo, bar=baz)

In the above example, :func:`my_function` will be executed every time
:meth:`Engine.poll <pants.engine.Engine.poll>` is called. That is, on every
subsequent iteration of the main loop.


Deferreds
=========

A deferred is a function that is executed after a certain amount of time has
passed. Deferreds are created by using the
:meth:`Engine.defer() <pants.engine.Engine.defer>` method::

    cancel_deferred = engine.defer(5.0, my_function, foo, bar=baz)

In the above example, :func:`my_function` will be executed after 5 seconds.


Cycles
======

A cycle is a function that is executed at regular intervals. Cycles are
created by using the :meth:`Engine.cycle() <pants.engine.Engine.cycle>`
method::

    cancel_cycle = engine.cycle(10.0, my_function, foo, bar=baz)

In the above example, :func:`my_function` will be executed every 10 seconds.
