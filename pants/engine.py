###############################################################################
#
# Copyright 2009 Facebook (see CREDITS.txt)
# Copyright 2011 Pants Developers (see AUTHORS.txt)
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
The core of the Pants framework - the engine.
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
    The asynchronous engine that powers a Pants application.

    The engine is a singleton object responsible for updating all
    channels and timers in your application. Once started it will run
    until it is manually stopped, interrupted or a fatal error occurs.
    """
    # Socket events - these correspond to epoll() states.
    NONE = 0x00
    READ = 0x01
    WRITE = 0x04
    ERROR = 0x08
    HANGUP = 0x10 | 0x2000
    ALL_EVENTS = READ | WRITE | ERROR | HANGUP

    def __init__(self):
        self.time = time.time()

        self._shutdown = False
        self._running = False

        self._channels = {}
        self._poller = None
        self._install_poller()

        self._callbacks = []
        self._deferreds = []

    @classmethod
    def instance(cls):
        """
        Return the global engine object.
        """
        if not hasattr(cls, "_instance"):
            cls._instance = cls()

        return cls._instance

    ##### Engine Methods ######################################################

    def start(self, poll_timeout=0.02):
        """
        Start the engine.

        This method initialises and continuously polls the engine until
        either :meth:`~pants.engine.Engine.stop` is called, or an uncaught
        :obj:`Exception` is raised. :meth:`~pants.engine.Engine.start`
        should be called after your asynchronous application has been fully
        initialised. For applications with a pre-existing main loop, see
        :meth:`~pants.engine.Engine.poll`.

        =============  ============
        Argument       Description
        =============  ============
        poll_timeout   *Optional.* The timeout to pass to :meth:`~pants.engine.Engine.poll`. By default, is 0.02.
        =============  ============
        """
        if self._shutdown:
            self._shutdown = False
            return
        if self._running:
            return
        else:
            self._running = True

        # Initialise engine.
        log.info("Starting engine.")

        # Main loop.
        try:
            while not self._shutdown:
                self.poll(poll_timeout)
        except KeyboardInterrupt:
            pass
        except SystemExit:
            raise
        except Exception:
            log.exception("Uncaught exception in main loop.")
        finally:
            # Graceful shutdown.
            log.info("Stopping engine.")
            self._shutdown = False
            self._running = False

    def stop(self):
        """
        Stop the engine.

        If :meth:`~pants.engine.Engine.start` has been called, calling
        :meth:`~pants.engine.Engine.stop` will cause the engine to cease
        polling and shut down.
        """
        if self._running:
            self._shutdown = True

    def poll(self, poll_timeout):
        """
        Poll the engine.

        Update timers and perform I/O on all active channels. If your
        application has a pre-existing main loop, call
        :meth:`~pants.engine.Engine.poll` on each iteration of that loop,
        otherwise, see :meth:`~pants.engine.Engine.start`.

        ============= ============
        Argument      Description
        ============= ============
        poll_timeout  The timeout to be passed to the polling object.
        ============= ============
        """
        self.time = time.time()

        # Timers

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

        # Channels

        try:
            events = self._poller.poll(poll_timeout)
        except Exception, err:
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
                log.exception("Error while handling I/O events on %s #%d." %
                        (channel.__class__.__name__, fileno))

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
            log.exception("Error while removing %s #%d." %
                    (channel.__class__.__name__, channel.fileno))

    ##### Timer Methods #######################################################

    def callback(self, function, *args, **kwargs):
        """
        Schedule a callback.

        A callback is a function (or other callable) that is not executed
        immediately but rather at the beginning of the next iteration of the
        main engine loop.

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
        timer = _Timer(callback, False)
        self._callbacks.append(timer)

        return functools.partial(self._remove_timer, timer)

    def loop(self, function, *args, **kwargs):
        """
        Schedule a loop.

        A loop is a callback that is executed and then rescheduled, being
        run on each iteration of the main engine loop.

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
        timer = _Timer(loop, True)
        self._callbacks.append(timer)

        return functools.partial(self._remove_timer, timer)

    def defer(self, delay, function, *args, **kwargs):
        """
        Schedule a deferred.

        A deferred is a function (or other callable) that is not executed
        immediately but rather after a certain amount of time.

        Returns a callable which can be used to cancel the deferred.

        =========  ============
        Argument   Description
        =========  ============
        delay      The delay, in seconds, after which the deferred should be run.
        function   The callable to be executed when the deferred is run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        deferred = functools.partial(function, *args, **kwargs)
        timer = _Timer(deferred, False, delay, self.time + delay)
        bisect.insort(self._deferreds, timer)

        return functools.partial(self._remove_timer, timer)

    def cycle(self, interval, function, *args, **kwargs):
        """
        Schedule a cycle.

        A cycle is a deferred that is executed after a certain amount of
        time and then rescheduled, effectively being run at regular
        intervals.

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
        cycle = functools.partial(function, *args, **kwargs)
        timer = _Timer(cycle, True, interval, self.time + interval)
        bisect.insort(self._deferreds, timer)

        return functools.partial(self._remove_timer, timer)

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

    ##### Poller Methods ######################################################

    def _install_poller(self, poller=None):
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
    A simple data structure for storing timer information.

    =========  ============
    Argument   Description
    =========  ============
    function   The callable to be executed when the timer is run.
    requeue    Whether the timer should be requeued after being run.
    delay      The time, in seconds, after which the timer should be run - or None, for a callback/loop.
    end        The time, in seconds since the epoch, after which the timer should be run - or None, for a callback/loop.
    =========  ============
    """
    def __init__(self, function, requeue, delay=None, end=None):
        self.function = function
        self.requeue = requeue
        self.delay = delay
        self.end = end

    def __cmp__(self, to):
        return cmp(self.end, to.end)
