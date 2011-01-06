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

import pants.shared
from pants.shared import log


###############################################################################
# Scheduler Class
###############################################################################

class Scheduler(object):
    """
    The singleton scheduler class.
    
    Callbacks, deferreds and cycles can be scheduled on an instance of
    this class. Note that these objects rely on the existence of a
    global scheduler instance and on the engine regularly calling poll()
    on that instance. Other instances of this class will not function
    as expected, if at all.
    """
    def __init__(self):
        """
        Initialises the scheduler object.
        """
        self._callbacks = []
        self._deferreds = []
    
    ##### Control #############################################################
    
    def poll(self):
        """
        Update all callbacks, deferreds and cycles on the scheduler.
        """
        for callback in self._callbacks[:]:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
                callback.run()
        
        # The deferred list is sorted by time.
        while self._deferreds and self._deferreds[0].end <= pants.shared.time:
            deferred = self._deferreds.pop(0)
            deferred.run()
    
    ##### Interface ###########################################################
    
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
    
    def remove(self, obj):
        """
        Remove a callback, deferred or cycle from the scheduler.
        
        Parameters:
            obj - The callback, deferred or cycle to remove.
        """
        if isinstance(obj, Callback):
            self._callbacks.remove(obj)
        else:
            while obj in self._deferreds:
                self._deferreds.remove(obj)


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

#: The global scheduler object.
scheduler = Scheduler()
