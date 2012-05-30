###############################################################################
#
# Copyright 2011-2012 Pants Developers (see AUTHORS.txt)
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
The core Pants classes and objects.

Exports :class:`pants.basic.Client`, :class:`pants.basic.Connection`,
:class:`pants.basic.Server`, :class:`pants.stream.Stream`,
:class:`pants.stream.StreamServer` and the global
:class:`pants.engine.Engine` instance.
"""

###############################################################################
# Imports
###############################################################################

import logging

from pants.engine import Engine
from pants.basic import Client, Connection, Server
from pants.stream import Stream, StreamServer


###############################################################################
# Exports
###############################################################################

__authors__ = ["ecdavis", "Stendec"]
__version__ = "0.10.1"

__all__ = [
    "__authors__", "__version__",  # Metadata
    "engine",  # Core
    "Stream", "StreamServer",  # Low-level networking
    "Client", "Connection", "Server",  # High-level networking
    ]


###############################################################################
# Objects
###############################################################################

#: Alias for pants.engine.Engine.instance
engine = Engine.instance()


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
