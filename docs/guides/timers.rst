Using timers
************

There are four methods used for scheduling timers:
:meth:`Engine.callback() <pants.engine.Engine.callback>`,
:meth:`Engine.loop() <pants.engine.Engine.loop>`,
:meth:`Engine.defer() <pants.engine.Engine.defer>` and
:meth:`Engine.cycle() <pants.engine.Engine.cycle>`.
These methods all return a callable that can be used to cancel the timer
at any time::

    from pants import engine

    cancel_callback = engine.callback(callback)
    cancel_callback()

The timer methods can be passed any number of positional and keyword
arguments, which will then be passed through to the given function when
it is executed.
