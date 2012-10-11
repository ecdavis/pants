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

import logging
import re

from pants.stream import Stream

###############################################################################
# Logging
###############################################################################

log = logging.getLogger(__name__)

###############################################################################
# Constants
###############################################################################

__all__ = ('BaseIRC','IRCClient')

COMMAND = re.compile(r"((?::.+? )?)(.+?) (.*)")
NETMASK = re.compile(
    r":(?:(?:([^!\s]+)!)?([^@\s]+)@)?([A-Za-z0-9-/:?`[_^{|}\\\]\.]+)")
ARGS    = re.compile(r"(?:^|(?<= ))(:.*|[^ ]+)")
CTCP    = re.compile(r"([\x00\n\r\x10])")
unCTCP  = re.compile(r"\x10([0nr\x10])")

CODECS  = ('utf-8','iso-8859-1','cp1252')
#])" # this is here to correct syntax highlighting in textmate... remove it!!!

###############################################################################
# BaseIRC Class
###############################################################################

class BaseIRC(Stream):
    """
    The IRC protocol, implemented over a Pants :class:`~pants.stream.Stream`.

    The goal with this is to create a lightweight IRC class that can serve as
    either a server or a client. As such, it doesn't implement a lot of logic
    in favor of providing a robust base.

    The BaseIRC class can receive and send IRC commands, and automatically
    respond to certain commands such as PING.

    This class extends :class:`~pants.stream.Stream`, and as such has the same
    :func:`~pants.stream.Stream.connect` and :func:`~pants.stream.Stream.listen`
    functions.
    """
    def __init__(self, encoding='utf-8', **kwargs):
        Stream.__init__(self, **kwargs)

        # Set our prefix to an empty string. This is prepended to all sent
        # commands, and useful for servers.
        self.prefix = ''
        self.encoding = encoding

        # Read lines at once.
        self.read_delimiter = '\n'

    ##### Public Event Handlers ###############################################

    def irc_close(self):
        """
        Placeholder.

        This method is called whenever the IRC instance becomes disconnected
        from the remote client or server.
        """
        pass

    def irc_command(self, command, args, nick, user, host):
        """
        Placeholder.

        This method is called whenever a command is received from the other
        side and successfully parsed as an IRC command.

        =========  ============
        Argument   Description
        =========  ============
        command    The received command.
        args       A list of the arguments following the command.
        nick       The nick of the user that sent the command, if applicable, or an empty string.
        user       The username of the user that sent the command, if applicable, or an empty string.
        host       The host of the user that sent the command, the host of the server that sent the command, or an empty string if no host was supplied.
        =========  ============
        """
        pass

    def irc_connect(self):
        """
        Placeholder.

        This method is called when the IRC instance has successfully connected
        to the remote client or server.
        """
        pass

    ##### I/O Methods #########################################################

    def message(self, destination, message, _ctcpQuote=True, _prefix=None):
        """
        Send a message to the given nick or channel.

        ============  ========  ============
        Argument      Default   Description
        ============  ========  ============
        destination             The nick or channel to send the message to.
        message                 The text of the message to be sent.
        _ctcpQuote    True      *Optional.* If True, the message text will be quoted for CTCP before being sent.
        _prefix       None      *Optional.* A string that, if provided, will be prepended to the command string before it's sent to the server.
        ============  ========  ============
        """
        if _ctcpQuote:
            message = ctcpQuote(message)

        self.send_command("PRIVMSG", destination, message, _prefix=_prefix)

    def notice(self, destination, message, _ctcpQuote=True, _prefix=None):
        """
        Send a NOTICE to the specified destination.

        ===========  ========  ============
        Argument     Default   Description
        ===========  ========  ============
        destination            The nick or channel to send the NOTICE to.
        message                The text of the NOTICE to be sent.
        _ctcpQuote   True      *Optional.* If True, the message text will be quoted for CTCP before being sent.
        _prefix      None      *Optional.* A string that, if provided, will be prepended to the command string before it's sent to the server.
        ===========  ========  ============
        """
        if _ctcpQuote:
            message = ctcpQuote(message)

        self.send_command("NOTICE", destination, message, _prefix=_prefix)

    def quit(self, reason=None, _prefix=None):
        """
        Send a QUIT message, with an optional reason.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        reason     None      *Optional.* The reason for quitting that will be displayed to other users.
        _prefix    None      *Optional.* A string that, if provided, will be prepended to the command string before it's sent to the server.
        =========  ========  ============
        """
        if not reason:
            reason = "pants.contrib.irc -- http://www.pantsweb.org/"
        self.send_command("QUIT", reason, _prefix=_prefix)

    def send_command(self, command, *args, **kwargs):
        """
        Send a command to the remote endpoint.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        command              The command to send.
        \*args                *Optional.* A list of arguments to send with the command.
        _prefix    None      *Optional.* A string that, if provided, will be prepended to the command string before it's sent to the server.
        =========  ========  ============
        """
        if args:
            args = list(args)
            for i in xrange(len(args)):
                arg = args[i]
                if not isinstance(arg, basestring):
                    args[i] = str(arg)

            if not args[-1].startswith(':'):
                args[-1] = ':%s' % args[-1]

            out = '%s %s\r\n' % (command, ' '.join(args))
        else:
            out = '%s\r\n' % command

        if '_prefix' in kwargs and kwargs['_prefix']:
            out = '%s %s' % (kwargs['_prefix'], out)
        elif self.prefix:
            out = '%s %s' % (self.prefix, out)

        # Send it.
        log.debug('\x1B[0;32m>> %s\x1B[0m' % out.rstrip())

        self.write(out.encode(self.encoding))

    ##### Internal Event Handlers #############################################

    def on_command(self, command, args, nick, user, host):
        """
        Placeholder.

        Performs any logic that has to be performed upon receiving a command,
        then calls irc_command.

        Arguments are identical to irc_command.
        """
        if hasattr(self, 'irc_command_%s' % command):
            getattr(self, 'irc_command_%s' % command)(
                command, args, nick, user, host)
        else:
            self.irc_command(command, args, nick, user, host)

    def on_connect(self):
        """
        Placeholder.

        Performs any logic that has to be performed at connect, then calls
        self.irc_connect.
        """
        self.irc_connect()

    def on_close(self):
        """
        Placeholder.

        Performs any logic that has to be performed at disconnect, then calls
        self.irc_close.
        """
        self.irc_close()

    def on_read(self, data):
        """
        Read the available data, parse the command, and call an event for it.
        """
        data = data.strip('\r\n')
        if not data:
            return

        log.debug('\x1B[0;31m<< %s\x1B[0m' % repr(data)[1:-1])

        # Decode it straight away.
        data = decode(data)

        try:
            prefix, command, raw = COMMAND.match(data).groups()
        except Exception:
            log.warning('Invalid IRC command %r.' % data)
            return

        if prefix:
            nick, user, host = NETMASK.match(prefix).groups()
            if not nick and not '.' in host:
                nick = host
                host = ''
        else:
            nick, user, host = '', '', ''

        args = ARGS.findall(raw)
        if args:
            if args[-1].startswith(':'):
                args[-1] = args[-1][1:]

        # If it's PING, handle it.
        if command == 'PING':
            self.send_command('PONG', *args)
            return

        # Handle the command.
        self.on_command(command, args, nick, user, host)

###############################################################################
# IRCClient Class & Channel Class
###############################################################################

class Channel(object):
    """
    An IRC channel's representation, for keeping track of users and the topic
    and stuff.
    """
    __slots__ = ('name', 'users','topic','topic_setter','topic_time')

    def __init__(self, name):
        self.name = name
        self.users = []
        self.topic = None
        self.topic_setter = None
        self.topic_time = 0

class IRCClient(BaseIRC):
    """
    An IRC client, written in Pants, based on :class:`~pants.contrib.irc.BaseIRC`.

    This implements rather more logic, and keeps track of what server it's
    connected to, its nick, and what channels it's in.
    """
    def __init__(self, encoding='utf-8', **kwargs):
        BaseIRC.__init__(self, encoding=encoding, **kwargs)

        # Internal State Stuff
        self._channels  = {}
        self._joining   = []

        self._nick      = None
        self._port      = 6667
        self._server    = None
        self._user      = None
        self._realname  = None

        # External Stuff
        self.password   = None

    ##### Properties ##########################################################

    @property
    def nick(self):
        """
        This instance's current nickname on the server it's connected to, or
        the nickname it will attempt to acquire when connecting.
        """
        return self._nick

    @nick.setter
    def nick(self, val):
        if not self.connected:
            self._nick = val
        else:
            self.send_command("NICK", val)

    @property
    def port(self):
        """
        The port this instance is connected to on the remote server, or the
        port it will attempt to connect to.
        """
        return self._port

    @port.setter
    def port(self, val):
        if self.connected or self.connecting:
            raise IOError('Cannot change while connected to server.')
        self._port = val

    @property
    def realname(self):
        """
        The real name this instance will report to the server when connecting.
        """
        return self._realname

    @realname.setter
    def realname(self, val):
        if self.connected or self.connecting:
            raise IOError('Cannot change while connected to server.')
        self._realname = val

    @property
    def server(self):
        """
        The server this instance is connected to, or will attempt to connect to.
        """
        return self._server

    @server.setter
    def server(self, val):
        if self.connected or self.connecting:
            raise IOError('Cannot change while connected to server.')
        self._server = val

    @property
    def user(self):
        """
        The user name this instance will report to the server when connecting.
        """
        return self._user

    @user.setter
    def user(self, val):
        if self.connected or self.connecting:
            raise IOError('Cannot change while connected to server.')
        self._user = val

    ##### General Methods #####################################################

    def channel(self, name):
        """
        Retrieve a Channel object for the channel ``name``, or None if we're
        not in that channel.
        """
        return self._channels.get(name, None)

    def connect(self, server=None, port=None):
        """
        Connect to the server.

        =========  ============
        Argument   Description
        =========  ============
        server     The host to connect to.
        port       The port to connect to on the remote server.
        =========  ============
        """
        if not self.connected and not self.connecting:
            if server:
                self._server = server
            if port:
                self._port = port


        Stream.connect(self, (self._server, self._port))

    ##### I/O Methods #########################################################

    def join(self, channel):
        """
        Join the specified channel.

        =========  ============
        Argument   Description
        =========  ============
        channel    The name of the channel to join.
        =========  ============
        """
        if channel in self._channels or channel in self._joining:
            return

        self._joining.append(channel)
        self.send_command("JOIN", channel)

    def part(self, channel, reason=None, force=False):
        """
        Leave the specified channel.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        channel              The channel to leave.
        reason     None      *Optional.* The reason why.
        force      False     *Optional.* Don't ensure the client is actually *in* the named channel before sending ``PART``.
        =========  ========  ============
        """
        if not force and not channel in self._channels:
            return

        args = [channel]
        if reason:
            args.append(reason)

        self.send_command("PART", *args)

    ##### Public Event Handlers ###############################################

    def irc_ctcp(self, nick, message, user, host):
        """
        Placeholder.

        This method is called when the bot receives a CTCP message, which
        could, in theory, be anywhere in a PRIVMSG... annoyingly enough.

        =========  ============
        Argument   Description
        =========  ============
        nick       The nick of the user that sent the CTCP message, or an empty string if no nick is available.
        message    The full CTCP message.
        user       The username of the user that sent the CTCP message, or an empty string if no username is available.
        host       The host of the user that sent the CTCP message, or an empty string if no host is available.
        =========  ============
        """
        pass

    def irc_join(self, channel, nick, user, host):
        """
        Placeholder.

        This method is called when a user enters a channel. That also means
        that this function is called whenever this IRC client successfully
        joins a channel.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel a user has joined.
        nick       The nick of the user that joined the channel.
        user       The username of the user that joined the channel.
        host       The host of the user that joined the channel.
        =========  ============
        """
        pass

    def irc_message_channel(self, channel, message, nick, user, host):
        """
        Placeholder.

        This method is called when the client receives a message from a channel.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel the message was received in.
        message    The text of the message.
        nick       The nick of the user that sent the message.
        user       The username of the user that sent the message.
        host       The host of the user that sent the message.
        =========  ============
        """
        pass

    def irc_message_private(self, nick, message, user, host):
        """
        Placeholder.

        This method is called when the client receives a message from a user.

        =========  ============
        Argument   Description
        =========  ============
        nick       The nick of the user that sent the message.
        message    The text of the message.
        user       The username of the user that sent the message.
        host       The host of the user that sent the message.
        =========  ============
        """
        pass

    def irc_nick_changed(self, nick):
        """
        Placeholder.

        This method is called when the client's nick on the network is changed
        for any reason.

        =========  ============
        Argument   Description
        =========  ============
        nick       The client's new nick.
        =========  ============
        """
        pass

    def irc_part(self, channel, reason, nick, user, host):
        """
        Placeholder.

        This method is called when a leaves enters a channel. That also means
        that this function is called whenever this IRC client leaves a
        channel.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel that the user has left.
        reason     The provided reason message, or an empty string if there is no message.
        nick       The nick of the user that left the channel.
        user       The username of the user that left the channel.
        host       The host of the user that left the channel.
        =========  ============
        """
        pass

    def irc_topic_changed(self, channel, topic):
        """
        Placeholder.

        This method is called when the topic of a channel changes.

        =========  ============
        Argument   Description
        =========  ============
        channel    The channel which had its topic changed.
        topic      The channel's new topic.
        =========  ============
        """
        pass

    ##### IRC Command Handlers ################################################

    def irc_command_004(self, command, args, nick, user, host):
        """ 004 - Registered
            Syntax:
                004 server ver usermode chanmode

            The 004 command is sent once we've registered successfully with the
            server and can proceed to do normal IRC things.
        """
        # Check our nick.
        n = args[0]
        if n != self._nick:
            self._nick = n
            self.irc_nick_changed(n)

        self.irc_connect()

    def irc_command_332(self, command, args, nick, user, host):
        """ 332 - Channel Topic
            Syntax:
                332 channel :topic
        """
        chan, topic = args[-2:]
        if chan in self._channels:
            self._channels[chan].topic = topic

        self.irc_topic_changed(chan, topic)

    def irc_command_333(self, command, args, nick, user, host):
        """ 333 - Channel Topic (Extended)
            Syntax:
                333 channel nickname time
        """
        chan, nickname, time = args[-3:]
        if chan in self._channels:
            self._channels[chan].topic_setter = nickname
            try:
                self._channels[chan].topic_time = int(time)
            except ValueError:
                pass

    def irc_command_353(self, command, args, nick, user, host):
        """ 353 - Users in Channel
            Syntax:
                353 = channel: names
        """
        chan, names = args[-2:]
        if chan in self._channels:
            for name in names.split(' '):
                while name[0] in '@+':
                    name = name[1:]
                if not name in self._channels[chan].users:
                    self._channels[chan].users.append(name)

    def irc_command_JOIN(self, command, args, nick, user, host):
        """
        Received whenever a user, including ourself, joins a channel.
        """
        chan = args[0]

        if nick == self._nick:
            if chan in self._joining:
                self._joining.remove(chan)
            if not chan in self._channels:
                self._channels[chan] = Channel(chan)

        if chan in self._channels:
            name = nick
            while name[0] in '@+':
                name = name[1:]
            if not name in self._channels[chan].users:
                self._channels[chan].users.append(name)

        self.irc_join(chan, nick, user, host)

    def irc_command_PART(self, command, args, nick, user, host):
        """
        Received whenever a user, including ourself, leaves a channel.
        """
        chan = args[0]

        if nick == self._nick:
            if chan in self._joining:
                self._joining.remove(chan)
            if chan in self._channels:
                del self._channels[chan]

        if chan in self._channels:
            name = nick
            while name[0] in '@+':
                name = name[1:]
            if name in self._channels[chan].users:
                self._channels[chan].users.remove(name)

        if len(args) < 2:
            args.append('')

        self.irc_part(chan, args[1], nick, user, host)

    def irc_command_PRIVMSG(self, command, args, nick, user, host):
        """
        The PRIVMSG command is the heart of IRC communications. This method
        will call either irc_message_channel, or irc_message_private depending
        on the recipient of the privmsg.
        """
        msg = args[1]
        while msg:
            ind = msg.find('\x01')
            if ind == -1:
                ind = len(msg)

            if ind > 0:
                message = msg[:ind]
                msg = msg[ind:]

                if args[0] == self._nick:
                    self.irc_message_private(nick, message, user, host)
                else:
                    self.irc_message_channel(
                        args[0], message, nick, user, host)

            if msg:
                msg = msg[1:]
                ind = msg.find('\x01')
                if ind == -1:
                    continue

                message = msg[:ind]
                msg = msg[ind+1:]

                self.irc_ctcp(nick, message, user, host)

    ##### Internal Event Handlers #############################################

    def on_connect(self):
        """
        We're connected, so send the login stuff.
        """
        if self.password:
            self.send_command("PASS", self.password)

        self.send_command("NICK", self._nick or 'PantsIRC')

        # Our user and realname.
        self.send_command("USER",
            self._user or 'PantsIRC',
            0, '*',
            self._realname or 'pants.contrib.irc'
        )

        # And now, we wait. Don't raise irc_connect until we get a message
        # letting us know our connection was accepted.

    def on_close(self):
        """
        We've been disconnected.
        """
        self._channels  = {}
        self._joining   = []

        self.irc_close()

###############################################################################
# Helper Functions
###############################################################################

def ctcpQuote(message):
    """
    Low-level quote a message, adhering to the CTCP guidelines.
    """
    return CTCP.sub(_ctcpQuoter, message)

def _ctcpQuoter(match):
    m = match.group(1)
    if m == '\x00':
        return '\x100'
    elif m == '\n':
        return '\x10n'
    elif m == '\r':
        return '\x10r'
    elif m == '\x10':
        return '\x10\x10'
    else:
        return m

def ctcpUnquote(message):
    """
    Low-level unquote a message, adhering to the CTCP guidelines.
    """
    return unCTCP.sub(_ctcpUnquoter, message)

def _ctcpUnquoter(match):
    m = match.group(1)
    if m == '0':
        return '\x00'
    elif m == 'n':
        return '\n'
    elif m == 'r':
        return '\r'
    elif m == '\x10':
        return '\x10'
    else:
        return m

def decode(data):
    for codec in CODECS:
        try:
            return data.decode(codec)
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', 'ignore')
