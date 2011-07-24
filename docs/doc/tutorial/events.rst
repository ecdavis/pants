Events
******
Pants provides a very simple implementation of the `publish/subscribe
<http://en.wikipedia.org/wiki/Publish/subscribe>`_ event pattern. The basic
API provides an interface to the global publisher consisting of three functions
and a decorator: ``pants.publish()``, ``pants.subscribe()``, 
``pants.unsubscribe()`` and ``pants.event()``.

Subscribing to an Event
=======================
An event handler is a function (or other callable) that has been subscribed to
a particular event. Event handlers can be registered using the
``pants.event()`` decorator::

    from pants import event
    
    @event("foo")
    def on_foo():
        pass

Or by calling ``pants.subscribe()``::

    from pants import subscribe
    
    def on_foo():
        pass
    
    subscribe("foo", on_foo)

These two methods have equivalent results.

Publishing an Event
===================
An event is simply a label (typically a string). When that label is passed to
``pants.publish()``, all event handlers subscribed to that label will be
executed::

    from pants import publish
    
    publish("foo")

Positional and/or keyword arguments can be passed to ``pants.publish()``.
These arguments will be passed to all event handlers registered to the given
label::

    publish("foo", 1, 2, 3, bar="baz")

Unsubscribing from an Event
===========================
You may find it necessary to unsubscribe a particular event handler. This can
be done using ``pants.unsubscribe()``::

    from pants import unsubscribe
    
    unsubscribe("foo", on_foo)

You can unsubscribe all event handlers subscribed to a particular event::

    unsubsribe("foo")

You can unsubscribe a particular event handler from all events::

    unsubscribe(handler=on_foo)

And if you're feeling crazy, you can even unsubscribe every event handler from
every event::

    unsubscribe()
