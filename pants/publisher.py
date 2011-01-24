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

from pants.shared import log


###############################################################################
# Publisher Class
###############################################################################

class Publisher(object):
    """
    A class that implements the publish/subscribe event pattern.
    
    This class may be directly instantiated to create a standalone
    publisher object, or it may be inherited by another class to provide
    pub/sub capabilities to instances of that class.
    """
    def __init__(self):
        """
        Initialises the publisher object.
        """
        self._events = {}
    
    def event(self, event):
        """
        Decorator. Subscribe a function to an event.
        
        Parameters:
            event - The event identifier, typically a string.
        """
        def decorator(handler):
            self.subscribe(event, handler)
            return handler
        
        return decorator
    
    def publish(self, event, *args, **kwargs):
        """
        Publish an event.
        
        Parameters:
            event - The event identifier, typically a string.
            *args - Positional arguments to be passed to subscribers.
            **kwargs - Keyword arguments to be passed to subscribers.
        """
        if not event in self._events:
            return
        
        for handler in self._events[event]:
            try:
                handler(*args, **kwargs)
            except Exception:
                log.exception("Exception raised while executing event.")
    
    def subscribe(self, event, handler):
        """
        Subscribe a callable to an event.
        
        Parameters:
            event - The event identifier, typically a string.
            handler - A callable that will be executed whenever the
                event is published.
        """
        if not event in self._events:
            self._events[event] = []
        
        self._events[event].append(handler)
    
    def unsubscribe(self, event=None, handler=None):
        """
        Unsubscribe a callable from an event.
        
        An event and a callable can be passed to this method. If no
        event is passed, all callables will be unsubscribed from all
        events. If an event is passed without a callable, all callables
        will be unsubscribed from that event. If both an event and a
        callable are passed then the callable will be unsubscribed from
        the event.
        
        Note that if a callable is passed without an event, all
        callables will be unsubscribed from all events.
        
        Parameters:
            event - The event identifier, typically a string.
            handler - A callable subscribed to some number of events.
        """
        if event is None:
            self._events = {}
        elif handler is None:
            self._events[event] = []
        else:
            self._events[event].remove(handler)


###############################################################################
# Initialisation
###############################################################################

#: The global publisher object.
publisher = Publisher()
