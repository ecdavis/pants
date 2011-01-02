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
from pants.scheduler import scheduler


###############################################################################
# Exports
###############################################################################

__all__ = [
    "engine", # Core
    "Client", "Connection", "reactor", "Server", # Networking
    "event", "publish", # Publisher
    "callback", "cycle", "defer", # Scheduler
    ]


###############################################################################
# Functions
###############################################################################

#: Alias for pants.publisher.event
event = publisher.event

#: Alias for pants.publisher.publisher.publish
publish = publisher.publish

#: Alias for pants.scheduler.scheduler.callback
callback = scheduler.callback

#: Alias for pant.scheduler.scheduler.defer
defer = scheduler.defer

#: Alias for pants.scheduler.scheduler.cycle
cycle = scheduler.cycle


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
