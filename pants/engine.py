###############################################################################
#
# Copyright 2011 Pants (see AUTHORS.txt)
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

###############################################################################
# Imports
###############################################################################

import bisect
import errno
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
    :class:`~pants.channel.Channel` objects and timers in your
    application. Once started it will run until it is manually stopped,
    interrupted or a fatal error occurs.
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
        # Update time.
        self.time = time.time()

        # Update timers.
        for callback in self._callbacks[:]: # Copy list, since we modify it.
            try:
                self._callbacks.remove(callback)
            except ValueError:
                pass # Callback not present.
            finally:
                callback.run()

        while self._deferreds and self._deferreds[0].end <= self.time:
            # The deferred list is sorted by time.
            deferred = self._deferreds.pop(0)
            deferred.run()

        if self._shutdown:
            return

        if self._deferreds:
            timeout = self._deferreds[0].end - self.time
            if timeout > 0.0:
                poll_timeout = min(timeout, poll_timeout)

        # Update channels.
        if not self._channels:
            time.sleep(poll_timeout) # Don't burn CPU.
            return

        try:
            events = self._poller.poll(poll_timeout)
        except Exception, err:
            if err[0] == errno.EINTR:
                log.warning("Interrupted system call.", exc_info=True)
                return
            else:
                raise

        for fileno, events in events.iteritems():
            try:
                self._channels[fileno]._handle_events(events)
            except (IOError, OSError), err:
                if err[0] == errno.EPIPE:
                    # EPIPE: Broken pipe.
                    log.debug("Broken pipe on %s #%d." %
                            (self._channels[fileno].__class__.__name___, fileno))
                    # TODO Close channel here?
                    self._channels[fileno].close()
                else:
                    log.exception("Error while handling I/O events on %s #%d." %
                            (self._channels[fileno].__class__.__name__, fileno))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                log.exception("Error while handling I/O events on %s #%d." %
                        (self._channels[fileno].__class__.__name__, fileno))

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

    def callback(self, func, *args, **kwargs):
        """
        Schedule a callback.

        A callback is a function (or other callable) that is not executed
        immediately but rather at the beginning of the next iteration of the
        main engine loop.

        Returns an object which can be used to cancel the callback.

        =========  ============
        Argument   Description
        =========  ============
        func       The callable to be executed when the callback is run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        callback = _Callback(func, *args, **kwargs)
        self._callbacks.append(callback)

        return callback

    def loop(self, func, *args, **kwargs):
        """
        Schedule a loop.

        A loop is a callback that is executed and then rescheduled, being
        run on each iteration of the main engine loop.

        Returns an object which can be used to cancel the loop.

        =========  ============
        Argument   Description
        =========  ============
        func       The callable to be executed when the loop is run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        loop = _Loop(func, *args, **kwargs)
        self._callbacks.append(loop)

        return loop

    def defer(self, func, delay, *args, **kwargs):
        """
        Schedule a deferred.

        A deferred is a function (or other callable) that is not executed
        immediately but rather after a certain amount of time.

        Returns an object which can be used to cancel the deferred.

        =========  ============
        Argument   Description
        =========  ============
        func       The callable to be executed when the deferred is run.
        delay      The delay, in seconds, after which the deferred should be run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        deferred = _Deferred(func, delay, *args, **kwargs)
        bisect.insort(self._deferreds, deferred)

        return deferred

    def cycle(self, func, interval, *args, **kwargs):
        """
        Schedule a cycle.

        A cycle is a deferred that is executed after a certain amount of
        time and then rescheduled, effectively being run at regular
        intervals.

        Returns an object which can be used to cancel the cycle.

        =========  ============
        Argument   Description
        =========  ============
        func       The callable to be executed when the cycle is run.
        interval   The interval, in seconds, at which the cycle should be run.
        args       The positional arguments to be passed to the callable.
        kwargs     The keyword arguments to be passed to the callable.
        =========  ============
        """
        cycle = _Cycle(func, interval, *args, **kwargs)
        bisect.insort(self._deferreds, cycle)

        return cycle

    def remove_timer(self, timer):
        """
        Remove a timer from the engine.

        =========  ============
        Argument   Description
        =========  ============
        timer      The timer to be removed.
        =========  ============
        """
        if isinstance(timer, _Deferred):
            try:
                self._deferreds.remove(timer)
            except ValueError:
                pass # Callback not present.
        else:
            try:
                self._callbacks.remove(timer)
            except ValueError:
                pass # Callback not present.

    ##### Poller Methods ######################################################

    def _install_poller(self, poller=None):
        if self._poller is not None:
            for fileno, channel in self._channels.iteritems():
                self._poller.remove(fileno, channel._events)

        if poller is not None:
            self._poller = poller
        if hasattr(select, "epoll"):
            self._poller = _EPoll()
        elif hasattr(select, "kqueue"):
            self._poller = _KQueue()
        else:
            self._poller = _Select()

        for fileno, channel in self._channels.iteritems():
            self._poller.add(fileno, channel._events)

    def _destroy_poller(self):
        self._poller.destroy()


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
        epoll_events = self._epoll.poll(timeout)
        events = {}

        for fileno, event in epoll_events:
            events[fileno] = event

        return events


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
        kqueue_events = self._kqueue.control(None, _KQueue.MAX_EVENTS, timeout)
        events = {}

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
        r, w, e, = select.select(self._r, self._w, self._e, timeout)

        events = {}

        for fileno in r:
            events[fileno] = events.get(fileno, 0) | Engine.READ
        for fileno in w:
            events[fileno] = events.get(fileno, 0) | Engine.WRITE
        for fileno in e:
            events[fileno] = events.get(fileno, 0) | Engine.ERROR

        return events


###############################################################################
# _Callback Class
###############################################################################

class _Callback(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception:
            log.exception("Exception raised while executing callback '%s'." %
                    self.func.__name__)

    def cancel(self):
        Engine.instance().remove_timer(self)


###############################################################################
# _Loop Class
###############################################################################

class _Loop(_Callback):
    def run(self):
        _Callback.run(self)

        Engine.instance()._callbacks.append(self)


###############################################################################
# _Deferred Class
###############################################################################

class _Deferred(_Callback):
    def __init__(self, func, delay, *args, **kwargs):
        _Callback.__init__(self, func, *args, **kwargs)

        self.delay = delay
        self.end = Engine.instance().time + delay

    def __cmp__(self, to):
        return cmp(self.end, to.end)


###############################################################################
# _Cycle Class
###############################################################################

class _Cycle(_Deferred):
    def run(self):
        _Deferred.run(self)

        self.end = Engine.instance().time + self.delay
        bisect.insort(Engine.instance()._deferreds, self)
