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
    A simple implementation of the publish/subscribe event pattern.
    
    This class may be directly instantiated to create a standalone
    publisher object, or it may be inherited by another class to provide
    pub/sub capabilities to instances of that class.
    """
    def __init__(self):
        self._events = {}
    
    def event(self, event):
        """
        Decorator. Subscribe a function to an event.
        
        Args:
            event: The event identifier.
        """
        def decorator(handler):
            self.subscribe(event, handler)
            return handler
        
        return decorator
    
    def publish(self, event, *args, **kwargs):
        """
        Publish an event.
        
        Args:
            event: The event identifier.
            *args: Positional arguments to be passed to subscribers.
            **kwargs: Keyword arguments to be passed to subscribers.
        """
        if not event in self._events:
            return
        
        for handler in self._events[event][:]:
            try:
                handler(*args, **kwargs)
            except Exception:
                log.exception("Exception raised while executing event.")
    
    def subscribe(self, event, handler):
        """
        Subscribe a handler to an event.
        
        Args:
            event: The event identifier.
            handler: A callable that will be executed when the event is
                published.
        """
        if not event in self._events:
            self._events[event] = []
        
        self._events[event].append(handler)
    
    def unsubscribe(self, event=None, handler=None):
        """
        Unsubscribe a handler from an event.
        
        Both of this method's arguments are optional. If no handler is
        passed, all handlers will be unsubscribed from the given event.
        If no event is passed, the given handler will be unsubscribed
        from all events. If neither an event nor a handler is passed,
        all handlers will be unsubscribed from all events.
        
        Args:
            event: The event identifier.
            handler: A callable subscribed to some number of events.
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

publisher = Publisher()
