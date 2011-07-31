``pants.contrib.irc``
*********************

.. automodule:: pants.contrib.irc


BaseIRC
=======

.. autoclass:: BaseIRC
    :members: message, notice, quit, send_command, irc_close, irc_command, irc_connect

Channel
=======

.. autoclass:: Channel

IRCClient
=========

.. autoclass:: IRCClient
    :members: nick, port, realname, server, user, channel, connect, join, part, irc_ctcp, irc_join, irc_message_channel, irc_message_private, irc_nick_changed, irc_part, irc_topic_changed

Helper Functions
================

.. autofunction:: ctcpQuote

.. autofunction:: ctcpUnquote

