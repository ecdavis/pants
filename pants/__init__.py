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

Exports the global engine, :class:`pants.stream.Stream` and
:class:`pants.server.Server`.
"""

###############################################################################
# Imports
###############################################################################

import logging

from pants._channel import HAS_IPV6, HAS_UNIX
from pants.engine import Engine
from pants.server import Server
from pants.stream import Stream
from pants.util.struct_delimiter import struct_delimiter


###############################################################################
# Exports
###############################################################################

__authors__ = ["ecdavis", "Stendec"]
__version__ = "1.0.0-beta.1"

__all__ = [
    "__authors__", "__version__",  # Metadata
    "HAS_IPV6", "HAS_UNIX",  # Constants
    "engine",  # Core
    "Stream", "Server",  # TCP Networking
    "struct_delimiter",  # Utility Stuff
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
