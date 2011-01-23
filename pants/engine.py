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
import time

from pants.publisher import publisher
from pants.reactor import reactor
import pants.shared
from pants.shared import log


###############################################################################
# Engine Class
###############################################################################

class Engine(object):
    """
    The singleton engine class.
    
    An instance of this class will initialise and continuously update
    the various parts of the Pants framework. The global instance of
    this class will suit almost all situations, and only one instance
    should be running at any given time.
    """
    def __init__(self):
        self.shutdown = False
        self.poll_timeout = 0.02 # Timeout passed to reactor.
        
        self._callbacks = []
        self._deferreds = []
    
    def poll(self):
        """
        Placeholder. Called on each iteration of the main loop.
        """
        pass
    
    def start(self, poll_timeout=0.02):
        """
        Start the engine.
        
        This method blocks until the engine is stopped. It should be
        called after your asynchronous application has been fully
        initialised and is ready to start.
        """
        if self.shutdown:
            self.shutdown = False
            return
        
        self.poll_timeout = poll_timeout
        
        # Initialise engine.
        log.info("Starting engine.")
        publisher.publish("pants.engine.start")
        
        # Main loop.
        try:
            log.info("Entering main loop.")
            
            while not self.shutdown:
                pants.shared.time = time.time()
                self.scheduler_update()
                
                if self.shutdown:
                    break
                
                poll_timeout = self.poll_timeout
                if self._deferreds:
                    timeout = self._deferreds[0].end - pants.shared.time
                    poll_timeout = min(timeout, poll_timeout)
                
                self.poll()
                
                if self.shutdown:
                    break
                
                reactor.poll(poll_timeout)
                publisher.publish("pants.engine.poll")
                
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception:
            log.exception("Uncaught exception in main loop.")
        
        # Graceful shutdown.
        log.info("Stopping engine.")
        publisher.publish("pants.engine.stop")
        
        log.info("Shutting down.")
        self.shutdown = False # If we decide to start up again.
    
    def stop(self):
        """
        Shut down the engine after the current main loop iteration.
        """
        self.shutdown = True
    
    ##### Scheduler Methods ###################################################
    
    def scheduler_update(self):
        """
        Update all callbacks, deferreds and cycles.
        """
        for callback in self._callbacks[:]:
            # Callbacks can remove other callbacks.
            if callback in self._callbacks:
                self._callbacks.remove(callback)
                callback.run()
        
        # The deferred list is sorted by time.
        while self._deferreds and self._deferreds[0].end <= pants.shared.time:
            deferred = self._deferreds.pop(0)
            deferred.run()
    
    def scheduler_remove(self, obj):
        """
        Remove a callback, deferred or cycle from the scheduler.
        
        Parameters:
            obj - The callback, deferred or cycle to remove.
        """
        if isinstance(obj, Deferred):
            while obj in self._deferreds:
                self._deferreds.remove(obj)
        else:
            self._callbacks.remove(obj)
    
    def callback(self, func, *args, **kwargs):
        """
        Schedule a callback.
        
        Parameters:
            func - A callable that will be executed when the callback is
                run.
            *args - Positional arguments to be passed to the callback.
            **kwargs - Keyword arguments to be passed to the callback.
        """
        callback = Callback(self, func, *args, **kwargs)
        self._callbacks.append(callback)
        
        return callback

    def defer(self, func, delay, *args, **kwargs):
        """
        Schedule a deferred.
        
        Parameters:
            func - A callable that will be executed when the deferred is
                run.
            delay - The delay, in seconds, before the deferred is run.
            *args - Positional arguments to be passed to the deferred.
            **kwargs - Keyword arguments to be passed to the deferred.
        """
        deferred = Deferred(self, func, delay, *args, **kwargs)
        bisect.insort(self._deferreds, deferred)
        
        return deferred
    
    def cycle(self, func, delay, *args, **kwargs):
        """
        Schedule a cycle.
        
        Parameters:
            func - A callable that will be executed when the cycle is
                run.
            interval - The interval, in seconds, at which the cycle is
                run.
            *args - Positional arguments to be passed to the cycle.
            **kwargs - Keyword arguments to be passed to the cycle.
        """
        cycle = Cycle(self, func, delay, *args, **kwargs)
        bisect.insort(self._deferreds, cycle)
        
        return cycle


###############################################################################
# Callback Class
###############################################################################

class Callback(object):
    """
    The callback class.
    
    A callback is a function (or other callable) that is not executed
    immediately but rather at the beginning of the next iteration of the
    main engine loop.
    """
    def __init__(self, scheduler, func, *args, **kwargs):
        self._scheduler = scheduler
        
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        """
        Execute the callback.
        """
        try:
            self.func(*self.args, **self.kwargs)
        except Exception:
            log.exception("Exception raised while executing callback.")
    
    def cancel(self):
        """
        Stop the callback from being executed.
        """
        self._scheduler.remove(self)


###############################################################################
# Deferred Class
###############################################################################

class Deferred(Callback):
    """
    The deferred class.
    
    A deferred is a function (or other callable) that is not executed
    immediately but rather after a certain amount of time.
    """
    def __init__(self, scheduler, func, delay, *args, **kwargs):
        Callback.__init__(self, scheduler, func, *args, **kwargs)
        
        self.delay = delay
        self.end = pants.shared.time + delay
    
    def __cmp__(self, to):
        return cmp(self.end, to.end)


###############################################################################
# Cycle Class
###############################################################################

class Cycle(Deferred):
    """
    The cycle class.
    
    A cycle is a deferred that is executed after a certain amount of
    time and then rescheduled, effectively being run at regular
    intervals.
    """
    def run(self):
        """
        Execute and reschedule the cycle.
        """
        Deferred.run(self)
        
        self._scheduler.cycle(self.func, self.delay, *self.args, **self.kwargs)


###############################################################################
# Initialisation
###############################################################################

#: The global engine object.
engine = Engine()
