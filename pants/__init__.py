###############################################################################
#
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
A convenient collection of the core Pants classes and methods to allow
imports from the top-level package.
"""

###############################################################################
# Imports
###############################################################################

import logging

from pants.engine import Engine
from pants.datagram import Datagram
from pants.network import Client, Connection, Server
from pants.stream import Stream, StreamServer

try:
    from pants.unix import UnixClient, UnixConnection, UnixServer
except ImportError:
    pass

###############################################################################
# Exports
###############################################################################

__authors__ = ["Christopher Davis", "Stendec"]
__version__ = "0.10.0"

__all__ = [
    "engine", # Core
    "callback", "loop", "cycle", "defer",  # Scheduling
    "Datagram", "Stream", "StreamServer",  # Low-level networking
    "Client", "Connection", "Server",  # High-level networking
    ]

if "UnixClient" in globals():
    __all__.extend([
        "UnixClient", "UnixConnection", "UnixServer", # High-level networking
    ])

###############################################################################
# Properties
###############################################################################

#: Alias for pants.engine.Engine.instance
engine = Engine.instance()


###############################################################################
# Functions
###############################################################################

#: Alias for pants.engine.Engine.instance().callback
callback = engine.callback

#: Alias for pants.engine.Engine.instance().loop
loop = engine.loop

#: Alias for pants.engine.Engine.instance().defer
defer = engine.defer

#: Alias for pants.engine.Engine.instance().cycle
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
