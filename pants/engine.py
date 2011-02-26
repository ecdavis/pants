###############################################################################
#
# Copyright 2011 Chris Davis
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

from pants.publisher import Publisher


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
    The singleton engine class.
    """
    # Socket events - these correspond to epoll() states.
    NONE = 0x00
    READ = 0x01
    WRITE = 0x04
    ERROR = 0x08 | 0x10 | 0x2000
    
    def __init__(self, poller=None):
        self.time = time.time()
        
        self._shutdown = False
        self._running = False
        
        self._channels = {}
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
        
        This method blocks until the engine is stopped. It should be
        called after your asynchronous application has been fully
        initialised and is ready to start.
        
        Args:
            poll_timeout: The timeout to pass to engine.poll().
        
        Raises:
            SystemExit
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
        Publisher.instance().publish("pants.engine.start")
        
        # Main loop.
        try:
            log.info("Entering main loop.")
            
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
            Publisher.instance().publish("pants.engine.stop")
            
            log.info("Shutting down.")
            self._shutdown = False
            self._running = False
    
    def stop(self):
        """
        Shut down the engine after the current main loop iteration.
        """
        self._shutdown = True
    
    def poll(self, poll_timeout):
        """
        Polls the engine.
        
        Updates all callbacks, deferreds and cycles. Identifies active
        sockets, then reads from, writes to and raises exceptions on
        those sockets.
        
        Args:
            timeout: The timeout to be passed to the polling object.
                Defaults to 0.02.
        """
        # Update time.
        self.time = time.time()
        
        # Update timers.
        for callback in self._callbacks[:]:
            # Callbacks can remove one another.
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
            timeout = min(timeout, poll_timeout)
            if timeout < 0:
                timeout = 0.0
        
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
                    self._channels[fileno].close_immediately()
                else:
                    log.exception("Error while handling I/O events on channel %d." % fileno)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                log.exception("Error while handling I/O events on channel %d." % fileno)
    
    ##### Channel Methods #####################################################
    
    def add_channel(self, channel):
        """
        Adds a channel to the engine.
        
        Args:
            channel: The channel to add.
        """
        self._channels[channel.fileno] = channel
        self._poller.add(channel.fileno, channel._events)
    
    def modify_channel(self, channel):
        """
        Modifies a channel's state.
        
        Args:
            channel: The channel to modify.
        """
        self._poller.modify(channel.fileno, channel._events)
    
    def remove_channel(self, channel):
        """
        Removes a channel from the engine.
        
        Args:
            channel: The channel to remove.
        """
        self._channels.pop(channel.fileno, None)
        
        try:
            self._poller.remove(channel.fileno)
        except (IOError, OSError):
            log.exception("Error while removing channel %d." % channel.fileno)
    
    ##### Timer Methods #######################################################
    
    def callback(self, func, *args, **kwargs):
        """
        Schedule a callback.
        
        Args:
            func: A callable to be executed when the callback is run.
            *args: Positional arguments to be passed to the callback.
            **kwargs: Keyword arguments to be passed to the callback.
        
        Returns:
            An object which can be used to cancel the callback.
        """
        callback = _Callback(func, *args, **kwargs)
        self._callbacks.append(callback)
        
        return callback
    
    def loop(self, func, *args, **kwargs):
        """
        Schedule a loop.
        
        Args:
            func: A callable to be executed when the loop is run.
            *args: Positional arguments to be passed to the loop.
            **kwargs: Keyword arguments to be passed to the loop.
        
        Returns:
            An object which can be used to cancel the loop.
        """
        loop = _Loop(func, *args, **kwargs)
        self._callbacks.append(loop)
        
        return loop
    
    def defer(self, func, delay, *args, **kwargs):
        """
        Schedule a deferred.
        
        Args:
            func: A callable to be executed when the deferred is run.
            delay: The delay, in seconds, before the deferred is run.
            *args: Positional arguments to be passed to the deferred.
            **kwargs: Keyword arguments to be passed to the deferred.
        
        Returns:
            An object which can be used to cancel the deferred.
        """
        deferred = _Deferred(func, delay, *args, **kwargs)
        bisect.insort(self._deferreds, deferred)
        
        return deferred
    
    def cycle(self, func, interval, *args, **kwargs):
        """
        Schedule a cycle.
        
        Args:
            func: A callable to be executed when the cycle is run.
            interval: The interval, in seconds, at which the cycle is
                run.
            *args: Positional arguments to be passed to the cycle.
            **kwargs: Keyword arguments to be passed to the cycle.
        
        Returns:
            An object which can be used to cancel the cycle.
        """
        cycle = _Cycle(func, interval, *args, **kwargs)
        bisect.insort(self._deferreds, cycle)
        
        return cycle
    
    def remove_timer(self, timer):
        """
        Remove a callback, deferred or cycle from the engine.
        
        Args:
            obj: The callback, deferred or cycle to remove.
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
            self._destroy_poller()
        
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
    
    def _destroy_poller(self):
        self._poller.destroy()


###############################################################################
# _Poller Class
###############################################################################

class _Poller(object):
    def add(self, fileno, events):
        pass
    
    def modify(self, fileno, events):
        pass
    
    def remove(self, fileno):
        pass
    
    def poll(self, timeout):
        pass
    
    def destroy(self):
        pass


###############################################################################
# _EPoll Class
###############################################################################

class _EPoll(_Poller):
    """
    An epoll()-based polling object.
    
    epoll() can only be used on Linux 2.6+
    """
    def __init__(self):
        self._epoll = select.epoll()
    
    def add(self, fileno, events):
        self._epoll.register(fileno, events)
    
    def modify(self, fileno, events):
        self._epoll.modify(fileno, events)
    
    def remove(self, fileno):
        self._epoll.unregister(fileno)
    
    def poll(self, timeout):
        epoll_events = self._epoll.poll(timeout)
        events = {}
        
        for fileno, event in epoll_events:
            if event & select.EPOLLIN:
                events[fileno] = events.get(fileno, 0) | Engine.READ
            if event & select.EPOLLOUT:
                events[fileno] = events.get(fileno, 0) | Engine.WRITE
            if event & (select.EPOLLERR | select.EPOLLHUP | 0x2000):
                events[fileno] = events.get(fileno, 0) | Engine.ERROR
        
        return events


###############################################################################
# _KQueue Class
###############################################################################

class _KQueue(_Poller):
    """
    A kqueue()-based polling object.
    
    kqueue() can only be used on BSD.
    """
    def __init__(self):
        self._kqueue = select.kqueue()
    
    def add(self, fileno, events):
        self._control(fileno, events, select.KQ_EV_ADD)
    
    def modify(self, fileno, events):
        self.remove(fileno)
        self.add(fileno, events)
    
    def remove(self, fileno):
        self._control(fileno, Engine.NONE, select.KQ_EV_DELETE)
    
    def poll(self, timeout):
        kqueue_events = self._kqueue.control(None, 1024, timeout)
        events = {}
        
        for event in kqueue_events:
            fileno = event.ident
            
            if event.filter == select.KQ_FILTER_READ:
                events[fileno] = events.get(fileno, 0) | Engine.READ
            if event.filter == select.KQ_FILTER_WRITE:
                events[fileno] = events.get(fileno, 0) | Engine.WRITE
            if event.flags & select.KQ_EV_ERROR:
                events[fileno] = events.get(fileno, 0) | Engine.ERROR
        
        return events
    
    def _control(self, fileno, events, flags):
        kqueue_events = []
        
        if events & Engine.WRITE:
            event = select.kevent(fileno, filter=select.KQ_FILTER_WRITE,
                                  flags=flags)
            kqueue_events.append(event)
        
        if events & Engine.READ or not kqueue_events:
            event = select.kevent(fileno, filter=select.KQ_FILTER_READ,
                                  flags=flags)
            kqueue_events.append(event)
        
        for event in kqueue_events:
            self._kqueue.control([event], 0)


###############################################################################
# _Select Class
###############################################################################

class _Select(_Poller):
    """
    A select()-based polling object.
    
    select()'s performance is relatively poor. On Windows, it is limited
    to 512 file descriptors.
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
        self.remove(fileno)
        self.add(fileno, events)
    
    def remove(self, fileno):
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
    """
    A callback is a function (or other callable) that is not executed
    immediately but rather at the beginning of the next iteration of the
    main engine loop.
    """
    def __init__(self, engine, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception:
            log.exception("Exception raised while executing callback.")
    
    def cancel(self):
        """
        Stop the callback from being executed.
        """
        Engine.instance().remove(self)


###############################################################################
# _Loop Class
###############################################################################

class _Loop(object):
    def run(self):
        _Callback.run(self)
        
        Engine.instance()._callbacks.append(self)


###############################################################################
# _Deferred Class
###############################################################################

class _Deferred(_Callback):
    """
    A deferred is a function (or other callable) that is not executed
    immediately but rather after a certain amount of time.
    """
    def __init__(self,  func, delay, *args, **kwargs):
        _Callback.__init__(self, func, *args, **kwargs)
        
        self.delay = delay
        self.end = engine.time + delay
    
    def __cmp__(self, to):
        return cmp(self.end, to.end)


###############################################################################
# _Cycle Class
###############################################################################

class _Cycle(_Deferred):
    """
    A cycle is a deferred that is executed after a certain amount of
    time and then rescheduled, effectively being run at regular
    intervals.
    """
    def run(self):
        _Deferred.run(self)
        
        self.end = Engine.instance().time + self.delay
        bisect.insort(Engine.instance()._deferreds, self)
