###############################################################################
#
# Copyright 2009 Facebook (see NOTICE.txt)
# Copyright 2011-2012 Pants Developers (see AUTHORS.txt)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
Asynchronous event processing and timer scheduling.
"""

###############################################################################
# Imports
###############################################################################

import bisect
import errno
import functools
import select
import time


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Engine Class
###############################################################################

class Engine(object):
    """
    The asynchronous engine class.

    An engine object is responsible for passing I/O events to active
    channels and running timers asynchronously. Depending on OS support,
    the engine will use either the epoll(), kqueue() or select() system
    call to detect events on active channels. It is possible to force
    the engine to use a particular polling method, but this is not
    recommended.

    Most applications will use the global engine object, which can be
    accessed using :meth:`~pants.engine.Engine.instance`, however it is
    also possible to create and use multiple instances of
    :class:`~pants.engine.Engine` in your application.

    An engine can either provide the main loop for your application
    (see :meth:`~pants.engine.Engine.start` and
    :meth:`~pants.engine.Engine.stop`), or its functionality can be
    integrated into a pre-existing main loop (see
    :meth:`~pants.engine.Engine.poll`).

    =========  =========================================================
    Argument   Description
    =========  =========================================================
    poller     *Optional.* A specific polling object for the engine to
               use.
    =========  =========================================================
    """
    # Socket events - these correspond to epoll() states.
    NONE = 0x00
    READ = 0x01
    WRITE = 0x04
    ERROR = 0x08
    HANGUP = 0x10 | 0x2000
    BASE_EVENTS = READ | ERROR | HANGUP
    ALL_EVENTS = BASE_EVENTS | WRITE

    def __init__(self, poller=None):
        self.time = time.time()

        self._shutdown = False
        self._running = False

        self._channels = {}
        self._poller = None
        self._install_poller(poller)

        self._callbacks = []
        self._deferreds = []

    @classmethod
    def instance(cls):
        """
        Returns the global engine object.
        """
        if not hasattr(cls, "_instance"):
            cls._instance = cls()

        return cls._instance

    ##### Engine Methods ######################################################

    def start(self, poll_timeout=0.02):
        """
        Start the engine.

        Initialises and continuously polls the engine until either
        :meth:`~pants.engine.Engine.stop` is called or an uncaught
        :obj:`Exception` is raised. :meth:`~pants.engine.Engine.start`
        should be called after your asynchronous application has been fully
        initialised. For applications with a pre-existing main loop, see
        :meth:`~pants.engine.Engine.poll`.

        =============  ===================================
        Argument       Description
        =============  ===================================
        poll_timeout   *Optional.* The timeout to pass to
                       :meth:`~pants.engine.Engine.poll`.
        =============  ===================================
        """
        if self._shutdown:
            self._shutdown = False
            return
        if self._running:
            return
        else:
            self._running = True

        log.info("Starting engine.")

        try:
            while not self._shutdown:
                self.poll(poll_timeout)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            log.exception("Uncaught exception in main loop.")
        finally:
            log.info("Stopping engine.")
            self._shutdown = False
            self._running = False

    def stop(self):
        """
        Stop the engine.

        If :meth:`~pants.engine.Engine.start` has been called, calling
        :meth:`~pants.engine.Engine.stop` will cause the engine to cease
        polling and shut down on the next iteration of the main loop.
        """
        if self._running:
            self._shutdown = True

    def poll(self, poll_timeout):
        """
        Poll the engine.

        Updates timers and processes I/O events on all active channels.
        If your application has a pre-existing main loop, call
        :meth:`~pants.engine.Engine.poll` on each iteration of that
        loop, otherwise, see :meth:`~pants.engine.Engine.start`.

        ============= ============
        Argument      Description
        ============= ============
        poll_timeout  The timeout to be passed to the polling object.
        ============= ============
        """
        self.time = time.time()

        callbacks, self._callbacks = self._callbacks[:], []

        for timer in callbacks:
            try:
                timer.function()
            except Exception:
                log.exception("Exception raised while executing timer.")

            if timer.requeue:
                self._callbacks.append(timer)

        while self._deferreds and self._deferreds[0].end <= self.time:
            timer = self._deferreds.pop(0)

            try:
                timer.function()
            except Exception:
                log.exception("Exception raised while executing timer.")

            if timer.requeue:
                timer.end = self.time + timer.delay
                bisect.insort(self._deferreds, timer)

        if self._shutdown:
            return

        if self._deferreds:
            timeout = self._deferreds[0].end - self.time
            if timeout > 0.0:
                poll_timeout = min(timeout, poll_timeout)

        if not self._channels:
            time.sleep(poll_timeout)  # Don't burn CPU.
            return

        try:
            events = self._poller.poll(poll_timeout)
        except Exception as err:
            if err[0] == errno.EINTR:
                log.debug("Interrupted system call.")
                return
            else:
                raise

        for fileno, events in events.iteritems():
            channel = self._channels[fileno]
            try:
                channel._handle_events(events)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                log.exception("Error while handling events on %r." % channel)

    ##### Timer Methods #######################################################

    def callback(self, function, *args, **kwargs):
        """
        Schedule a callback.

        A callback is a function (or other callable) that is executed
        the next time :meth:`~pants.engine.Engine.poll` is called - in
        other words, on the next iteration of the main loop.

        Returns a callable which can be used to cancel the callback.

        =========  ============
        Argument   Description
        =========  ============
        function   The callable to be executed when the callback is run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        callback = functools.partial(function, *args, **kwargs)
        timer = _Timer(self, callback, False)
        self._callbacks.append(timer)

        return timer

    def loop(self, function, *args, **kwargs):
        """
        Schedule a loop.

        A loop is a callback that is continuously rescheduled. It will
        be executed every time :meth:`~pants.engine.Engine.poll` is
        called - in other words, on each iteraton of the main loop.

        Returns a callable which can be used to cancel the loop.

        =========  ============
        Argument   Description
        =========  ============
        function   The callable to be executed when the loop is run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        loop = functools.partial(function, *args, **kwargs)
        timer = _Timer(self, loop, True)
        self._callbacks.append(timer)

        return timer

    def defer(self, delay, function, *args, **kwargs):
        """
        Schedule a deferred.

        A deferred is a function (or other callable) that is executed
        after a certain amount of time has passed.

        Returns a callable which can be used to cancel the deferred.

        =========  =====================================================
        Argument   Description
        =========  =====================================================
        delay      The delay, in seconds, after which the deferred
                   should be run.
        function   The callable to be executed when the deferred is run.
        args       The positional arguments to be passed to the
                   callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  =====================================================
        """
        if delay <= 0:
            raise ValueError("Delay must be greater than 0 seconds.")

        deferred = functools.partial(function, *args, **kwargs)
        timer = _Timer(self, deferred, False, delay, self.time + delay)
        bisect.insort(self._deferreds, timer)

        return timer

    def cycle(self, interval, function, *args, **kwargs):
        """
        Schedule a cycle.

        A cycle is a deferred that is continuously rescheduled. It will
        be run at regular intervals.

        Returns a callable which can be used to cancel the cycle.

        =========  ============
        Argument   Description
        =========  ============
        interval   The interval, in seconds, at which the cycle should be run.
        function   The callable to be executed when the cycle is run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        if interval <= 0:
            raise ValueError("Interval must be greater than 0 seconds.")

        cycle = functools.partial(function, *args, **kwargs)
        timer = _Timer(self, cycle, True, interval, self.time + interval)
        bisect.insort(self._deferreds, timer)

        return timer

    def _remove_timer(self, timer):
        """
        Remove a timer from the engine.

        =========  ============
        Argument   Description
        =========  ============
        timer      The timer to be removed.
        =========  ============
        """
        if timer.end is None:
            try:
                self._callbacks.remove(timer)
            except ValueError:
                pass  # Callback not present.
        else:
            try:
                self._deferreds.remove(timer)
            except ValueError:
                pass  # Callback not present.

    ##### Channel Methods #####################################################

    def add_channel(self, channel):
        """
        Add a channel to the engine.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel to be added.
        =========  ============
        """
        self._channels[channel.fileno] = channel
        self._poller.add(channel.fileno, channel._events)

    def modify_channel(self, channel):
        """
        Modify the state of a channel.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel to be modified.
        =========  ============
        """
        self._poller.modify(channel.fileno, channel._events)

    def remove_channel(self, channel):
        """
        Remove a channel from the engine.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel to be removed.
        =========  ============
        """
        self._channels.pop(channel.fileno, None)

        try:
            self._poller.remove(channel.fileno, channel._events)
        except (IOError, OSError):
            log.exception("Error while removing %r." % channel)

    ##### Poller Methods ######################################################

    def _install_poller(self, poller=None):
        """
        Install a poller on the engine.

        =========  ============
        Argument   Description
        =========  ============
        poller     The poller to be installed.
        =========  ============
        """
        if self._poller is not None:
            for fileno, channel in self._channels.iteritems():
                self._poller.remove(fileno, channel._events)

        if poller is not None:
            self._poller = poller
        elif hasattr(select, "epoll"):
            self._poller = _EPoll()
        elif hasattr(select, "kqueue"):
            self._poller = _KQueue()
        else:
            self._poller = _Select()

        for fileno, channel in self._channels.iteritems():
            self._poller.add(fileno, channel._events)


###############################################################################
# _EPoll Class
###############################################################################

class _EPoll(object):
    """
    An :obj:`~select.epoll`-based poller.
    """
    def __init__(self):
        self._epoll = select.epoll()

    def add(self, fileno, events):
        self._epoll.register(fileno, events)

    def modify(self, fileno, events):
        self._epoll.modify(fileno, events)

    def remove(self, fileno, events):
        self._epoll.unregister(fileno)

    def poll(self, timeout):
        return dict(self._epoll.poll(timeout))


###############################################################################
# _KQueue Class
###############################################################################

class _KQueue(object):
    """
    A :obj:`~select.kqueue`-based poller.
    """
    MAX_EVENTS = 1024

    def __init__(self):
        self._events = {}
        self._kqueue = select.kqueue()

    def add(self, fileno, events):
        self._events[fileno] = events
        self._control(fileno, events, select.KQ_EV_ADD)

    def modify(self, fileno, events):
        self.remove(fileno, self._events[fileno])
        self.add(fileno, events)

    def remove(self, fileno, events):
        self._control(fileno, events, select.KQ_EV_DELETE)
        self._events.pop(fileno, None)

    def poll(self, timeout):
        events = {}
        kqueue_events = self._kqueue.control(None, _KQueue.MAX_EVENTS, timeout)

        for event in kqueue_events:
            fileno = event.ident

            if event.filter == select.KQ_FILTER_READ:
                events[fileno] = events.get(fileno, 0) | Engine.READ
            if event.filter == select.KQ_FILTER_WRITE:
                events[fileno] = events.get(fileno, 0) | Engine.WRITE
            if event.flags & select.KQ_EV_ERROR:
                events[fileno] = events.get(fileno, 0) | Engine.ERROR
            if event.flags & select.KQ_EV_EOF:
                events[fileno] = events.get(fileno, 0) | Engine.HANGUP

        return events

    def _control(self, fileno, events, flags):
        if events & Engine.WRITE:
            event = select.kevent(fileno, filter=select.KQ_FILTER_WRITE,
                                  flags=flags)
            self._kqueue.control([event], 0)

        if events & Engine.READ:
            event = select.kevent(fileno, filter=select.KQ_FILTER_READ,
                                  flags=flags)
            self._kqueue.control([event], 0)


###############################################################################
# _Select Class
###############################################################################

class _Select(object):
    """
    A :func:`~select.select`-based poller.
    """
    def __init__(self):
        self._r = set()
        self._w = set()
        self._e = set()

    def add(self, fileno, events):
        if events & Engine.READ:
            self._r.add(fileno)
        if events & Engine.WRITE:
            self._w.add(fileno)
        if events & Engine.ERROR:
            self._e.add(fileno)

    def modify(self, fileno, events):
        self.remove(fileno, events)
        self.add(fileno, events)

    def remove(self, fileno, events):
        self._r.discard(fileno)
        self._w.discard(fileno)
        self._e.discard(fileno)

    def poll(self, timeout):
        # Note that select() won't raise "hangup" events. There's no way
        # around this and no way to determine whether a hangup or an
        # error occured. C'est la vie.
        events = {}
        r, w, e, = select.select(self._r, self._w, self._e, timeout)

        for fileno in r:
            events[fileno] = events.get(fileno, 0) | Engine.READ
        for fileno in w:
            events[fileno] = events.get(fileno, 0) | Engine.WRITE
        for fileno in e:
            events[fileno] = events.get(fileno, 0) | Engine.ERROR

        return events


###############################################################################
# _Timer Class
###############################################################################

class _Timer(object):
    """
    A simple class for storing timer information.

    =========  ======================================================
    Argument   Description
    =========  ======================================================
    function   The callable to be executed when the timer is run.
    requeue    Whether the timer should be requeued after being run.
    delay      The time, in seconds, after which the timer should be
               run- or None, for a callback/loop.
    end        The time, in seconds since the epoch, after which the
               timer should be run - or None, for a callback/loop.
    =========  ======================================================
    """
    def __init__(self, engine, function, requeue, delay=None, end=None):
        self.engine = engine
        self.function = function
        self.requeue = requeue
        self.delay = delay
        self.end = end

    def __call__(self):
        self.cancel()

    def __cmp__(self, to):
        return cmp(self.end, to.end)

    def cancel(self):
        self.engine._remove_timer(self)
