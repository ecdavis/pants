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
A tuple subclass that acts as a special read_delimiter that automates the use
of the ``struct`` module.
"""

###############################################################################
# Imports
###############################################################################

import operator
import struct

###############################################################################
# Constants and Storage
###############################################################################

_delimiters = {}

###############################################################################
# The Meta Class
###############################################################################

class DelimiterMeta(type):
    def __call__(cls, format):
        if format in _delimiters:
            return _delimiters[format]

        dlmt = _delimiters[format] = super(DelimiterMeta, cls).__call__(format)
        return dlmt

###############################################################################
# The struct_delimiter Class
###############################################################################

class struct_delimiter(tuple):

    __metaclass__ = DelimiterMeta

    def __new__(cls, format):
        # Create the tuple.
            return tuple.__new__(cls, (format, struct.calcsize(format)))

    def __getnewargs__(self):
        return self[0]

    def __repr__(self):
        return "struct_delimiter(%r)" % self[0]

    def pack(self, *args):
        return struct.pack(self[0], *args)

    def unpack(self, data):
        return struct.unpack(self[0], data)

    format = fmt = property(operator.itemgetter(0))
    length = property(operator.itemgetter(1))
