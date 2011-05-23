Engine
******

The :obj:`~pants.engine.Engine` is the core object of any Pants
application. It keeps track of every active :class:`~pants.channel.Channel`
and timer and continuously checks for new events, raising them on the
relevant :class:`~pants.channel.Channel` if necessary.

Applications
============


Timers
======

Callbacks
---------

Loops
-----

Deferreds
---------

Cycles
------

API
===

.. autoclass:: pants.engine.Engine
   :members: instance, start, stop, poll, callback, loop, defer, cycle
