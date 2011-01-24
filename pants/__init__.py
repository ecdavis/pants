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

import logging

from pants.engine import engine
from pants.network import Client, Connection, Server
from pants.publisher import publisher
from pants.reactor import reactor


###############################################################################
# Exports
###############################################################################

__author__ = "Christopher Davis"
__version__ = "0.9.3"

__all__ = [
    "engine", # Core
    "Client", "Connection", "Server", # Networking
    "event", "publish", "subscribe", "unsubscribe", # Publisher
    "callback", "cycle", "defer", # Scheduling
    ]


###############################################################################
# Functions
###############################################################################

#: Alias for pants.publisher.event
event = publisher.event

#: Alias for pants.publisher.publisher.publish
publish = publisher.publish

#: Alias for pants.publisher.publisher.subscribe
subscribe = publisher.subscribe

#: Alias for pants.publisher.publisher.unsubscribe
unsubscribe = publisher.unsubscribe

#: Alias for pants.engine.engine.callback
callback = engine.callback

#: Alias for pant.engine.engine.defer
defer = engine.defer

#: Alias for pants.engine.engine.cycle
cycle = engine.cycle


###############################################################################
# Logging
###############################################################################

class NullHandler(logging.Handler):
    """
    A dummy handler to prevent logging errors if the user does not
    initialise logging.
    """
    def emit(self, record):
        pass

logging.getLogger("pants").addHandler(NullHandler())
