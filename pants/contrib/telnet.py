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

from pants.network import Connection, Server


###############################################################################
# Constants
###############################################################################

# Telnet commands
IAC  = chr(255) # Interpret As Command
DONT = chr(254) # Don't Perform
DO   = chr(253) # Do Perform
WONT = chr(252) # Won't Perform
WILL = chr(251) # Will Perform
SB   = chr(250) # Subnegotiation Begin
SE   = chr(240) # Subnegotiation End


###############################################################################
# TelnetConnection Class
###############################################################################

class TelnetConnection(Connection):
    """
    A basic implementation of a Telnet connection.
    
    A TelnetConnection object is capable of identifying and extracting
    Telnet command sequences from incoming data. Upon identifying a
    Telnet command, option or subnegotiation, the connection will call a
    relevant placeholder method. This class should be subclassed to
    provide functionality for individual commands and options.
    """
    def __init__(self, server, socket):
        Connection.__init__(self, server, socket)
        
        self._telnet_recv_buffer = ""
        self._telnet_iac_sequence = ""
        self._telnet_sb_sequence = ""
    
    ##### Public Event Handlers ###############################################
    
    def on_read(self, data):
        """
        Reads incoming data and parses out Telnet command sequences.
        """
        for c in data:
            self._telnet_recv_byte(c)
        
        if len(self._telnet_recv_buffer) > 0:
            self.on_telnet_data(self._telnet_recv_buffer)
            self._telnet_recv_buffer = ""
    
    def on_telnet_data(self, data):
        """
        Placeholder. Called when the connection receives a chunk of data.
        
        Parameters:
            data - The received data.
        """
        pass
    
    def on_telnet_command(self, cmd):
        """
        Placeholder. Called when the connection recieves a Telnet
        command.
        
        Parameters
            cmd - The character representation of the Telnet command.
        """
        pass
    
    def on_telnet_option(self, cmd, opt):
        """
        Placeholder. Called when the connection receives an option
        negotiation sequence.
        
        Parameters:
            cmd - The character representation of the Telnet command.
            opt - The character representation of the Telnet option.
        """
        pass
    
    def on_telnet_subnegotiation(self, opt, arg):
        """
        Placeholder. Called when the connection receives a
        subnegotiation sequence.
        
        Parameters:
            opt - The character representation of the Telnet option.
            arg - The string representation of the subnegotiation.
        """
        pass
    
    ##### Internal Processing Methods #########################################
    
    def _telnet_recv_byte(self, c):
        """
        Reads a single character and adds it to the appropriate buffer
        depending on the current state of the connection.
        """
        iac_length = len(self._telnet_iac_sequence)
        
        if iac_length == 0:
            if c == IAC:
                # Begin IAC sequence.
                self._telnet_iac_sequence += c
            else:
                # Add to standard inbuf.
                self._telnet_recv_buffer += c
                
        elif iac_length == 1:
            if c == IAC:
                # Escaped IAC.
                self._telnet_recv_buffer += c
                self._telnet_iac_sequence = ""
            elif c in (DO, DONT, WILL, WONT):
                # Option negotiation.
                self._telnet_iac_sequence += c
            elif c == SB:
                # Subnegotiation.
                self._telnet_iac_sequence += c
            else:
                # Telnet command - call method and reset state.
                self.on_telnet_command(c)
                self._telnet_iac_sequence = ""
                
        elif iac_length == 2:
            last_byte = self._telnet_iac_sequence[-1]
            if last_byte in (DO, DONT, WILL, WONT):
                # Option negotiation - call method and reset state.
                self.on_telnet_option(last_byte, c)
                self._telnet_iac_sequence = ""
            elif last_byte == SB:
                # Subnegotiation - add option character to both IAC and
                # SB buffers.
                self._telnet_iac_sequence += c
                self._telnet_sb_sequence += c
            else:
                # TODO This shouldn't happen. Pretend it didn't.
                self._telnet_iac_sequence = ""
                
        elif iac_length == 3:
            if c == IAC:
                # Coming to the end of the subnegotiation?
                self._telnet_iac_sequence += c
            else:
                # Continuing the subnegotiation.
                self._telnet_sb_sequence += c
                
        elif iac_length == 4:
            if c == IAC:
                # Escaped IAC in the subnegotiation.
                self._telnet_iac_sequence = self._telnet_iac_sequence[:-1]
                self._telnet_sb_sequence += c
            elif c == SE:
                # Subnegotiation complete - call method and reset state.
                opt = self._telnet_sb_sequence[0]
                arg = self._telnet_sb_sequence[1:]
                self.on_telnet_subnegotiation(opt, arg)
                self._telnet_iac_sequence = ""
                self._telnet_sb_sequence = ""


###############################################################################
# TelnetServer Class
###############################################################################

class TelnetServer(Server):
    """
    A basic implementation of a Telnet server.
    """
    ConnectionClass = TelnetConnection
