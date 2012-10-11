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

###############################################################################
# Imports
###############################################################################

import re
import struct

from pants import Stream, Server
from pants.util.struct_delimiter import struct_delimiter


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger(__name__)


###############################################################################
# Constants
###############################################################################

RegexType = type(re.compile(""))

# Telnet commands
IAC  = chr(255)  # Interpret As Command
DONT = chr(254)  # Don't Perform
DO   = chr(253)  # Do Perform
WONT = chr(252)  # Won't Perform
WILL = chr(251)  # Will Perform
SB   = chr(250)  # Subnegotiation Begin
SE   = chr(240)  # Subnegotiation End

###############################################################################
# TelnetConnection Class
###############################################################################

class TelnetConnection(Stream):
    """
    A basic implementation of a Telnet connection.

    A TelnetConnection object is capable of identifying and extracting
    Telnet command sequences from incoming data. Upon identifying a
    Telnet command, option or subnegotiation, the connection will call a
    relevant placeholder method. This class should be subclassed to
    provide functionality for individual commands and options.
    """
    def __init__(self, **kwargs):
        Stream.__init__(self, **kwargs)

        # Initialize Stuff
        self._telnet_data = ""

    ##### Public Event Handlers ###############################################

    def on_command(self, command):
        """
        Placeholder. Called when the connection receives a telnet command,
        such as AYT (Are You There).

        =========  ============
        Argument   Description
        =========  ============
        command    The byte representing the telnet command.
        =========  ============
        """
        pass

    def on_option(self, command, option):
        """
        Placeholder. Called when the connection receives a telnet option
        negotiation sequence, such as IAC WILL ECHO.

        =========  ============
        Argument   Description
        =========  ============
        command    The byte representing the telnet command.
        option     The byte representing the telnet option being negotiated.
        =========  ============
        """
        pass

    def on_subnegotiation(self, option, data):
        """
        Placeholder. Called when the connection receives a subnegotiation
        sequence.

        =========  ============
        Argument   Description
        =========  ============
        option     The byte representing the telnet option for which subnegotiation data has been received.
        data       The received data.
        =========  ============
        """
        pass

    ##### Internal Telnet State Processing ####################################

    def _on_telnet_data(self, data):
        self._telnet_data += data

        while self._telnet_data:
            delimiter = self.read_delimiter

            if delimiter is None:
                data = self._telnet_data
                self._telnet_data = ''
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, (int, long)):
                if len(self._telnet_data) < delimiter:
                    break
                data = self._telnet_data[:delimiter]
                self._telnet_data = self._telnet_data[delimiter:]
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, basestring):
                mark = self._telnet_data.find(delimiter)
                if mark == -1:
                    break
                data = self._telnet_data[:mark]
                self._telnet_data = self._telnet_data[mark + len(delimiter):]
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, struct_delimiter):
                # Weird. Why are you using struct_delimiter in telnet? Silly
                # person. Anyways, blah blah blah, same comment as in the
                # delimiter handling everywhere else.
                if len(self._telnet_data) < delimiter[1]:
                    break
                data = self._telnet_data[:delimiter[1]]
                self._telnet_data = self._telnet_data[delimiter[1]:]

                try:
                    data = delimiter.unpack(data)
                except struct.error:
                    log.exception("Unable to unpack data on %r." % self)
                    self.close()
                    break

                self._safely_call(self.on_read, *data)

            elif isinstance(delimiter, RegexType):
                # Depending on regex_search, we could do this two ways.
                if self.regex_search:
                    match = delimiter.search(self._telnet_data)
                    if not match:
                        break

                    data = self._telnet_data[:match.start()]
                    self._telnet_data = self._telnet_data[match.end():]

                else:
                    data = delimiter.match(self._telnet_data)
                    if not data:
                        break
                    self._telnet_data = self._telnet_data[data.end():]

                self._safely_call(self.on_read, data)

            else:
                log.warning("Invalid read_delmiter on %r." % self)
                break

            if self._closed or not self.connected:
                break

    def _on_telnet_iac(self, data):
        if len(data) < 2:
            return False

        elif data[1] == IAC:
            # It's an escaped IAC byte. Send it to the data buffer.
            self._on_telnet_data(IAC)
            return data[2:]

        elif data[1] in '\xFB\xFC\xFD\xFE':
            if len(data) < 3:
                return False

            self._safely_call(self.on_option, data[1], data[2])
            return data[3:]

        elif data[1] == SB:
            seq = ''
            code = data[2:]
            data = data[3:]
            if not data:
                return False

            while data:
                loc = data.find(IAC)
                if loc == -1:
                    return False

                seq += data[:loc]

                if data[loc + 1] == SE:
                    # Match
                    data = data[loc+2:]
                    break

                elif data[loc + 1] == IAC:
                    # Escaped
                    seq += IAC
                    data = data[loc+2:]
                    continue

                # Unknown. Skip it.
                data = data[loc + 1:]
                if not data:
                    return False

            self._safely_call(self.on_subnegotiation, code, seq)

        # Still here? It must just be a command then. Send it on.
        self._safely_call(self.on_command, data[1])
        return data[2:]

    ##### Internal Processing Methods #########################################

    def _process_recv_buffer(self):
        """
        Completely replace the standard recv buffer processing with a custom
        function for optimal telnet performance.
        """
        while self._recv_buffer:
            loc = self._recv_buffer.find(IAC)

            if loc == -1:
                self._on_telnet_data(self._recv_buffer)
                self._recv_buffer = ''
                break

            elif loc > 0:
                self._on_telnet_data(self._recv_buffer[:loc])
                self._recv_buffer = self._recv_buffer[loc:]

            out = self._on_telnet_iac(self._recv_buffer)
            if out is False:
                break

            self._recv_buffer = out

###############################################################################
# TelnetServer Class
###############################################################################

class TelnetServer(Server):
    """
    A basic implementation of a Telnet server.
    """
    ConnectionClass = TelnetConnection
