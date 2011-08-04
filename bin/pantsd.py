#!/usr/bin/env python
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

###############################################################################
# Imports
###############################################################################

import functools
import logging
import logging.handlers
import optparse
import os
import socket
import sys
import tempfile

import pants

###############################################################################
# Constants & Variables
###############################################################################

commands = {}

COLORS = {
    'CRITICAL'  : 5,
    'DEBUG'     : 4,
    'ERROR'     : 1,
    'INFO'      : 7,
    'PANTS'     : 2,
    'WARNING'   : 3
    }

PANTS = logging.INFO + 1
logging.addLevelName(PANTS, 'PANTS')

###############################################################################
# Random Subclassing of Stuff
###############################################################################
class NiceParser(optparse.OptionParser):
    def format_epilog(self, formatter):
        return self.epilog

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, datefmt=None, use_color=True):
        logging.Formatter.__init__(self, msg, datefmt)
        self.use_color = use_color

    def format(self, record):
        level = record.levelname
        if self.use_color and level in COLORS:
            level_color = '\x1B[1;%dm%s\x1B[0m' % (30+COLORS[level], level)
            record.levelname = level_color
        return logging.Formatter.format(self, record)

###############################################################################
# Command Decorator
###############################################################################

def command(description, name=None):
    """ Register a new command for pantsd. """
    def decorator(func):
        nm = name if name else func.func_name
        commands[nm.lower()] = (description, func)

        return func
    return decorator

def parse_address(addr):
    if not ':' in addr:
        log.error("Invalid address supplied.")
        sys.exit(1)

    host, _, port = addr.rpartition(':')

    if host.lower() == 'unix':
        log.error("UNIX sockets are not available at this time.")
    else:
        try:
            port = int(port)
        except ValueError:
            log.error("Invalid address supplied.")
            sys.exit(1)
        return (host, port)

###############################################################################
# Commands
###############################################################################

@command("Import a script before starting the Pants engine.", name="file")
def run_files(global_options, arguments):
    if not arguments:
        print "Usage: %s [global-options] file [list of importable modules]" % os.path.basename(sys.argv[0])
        sys.exit(0)

    wd = os.getcwd()

    for f in arguments:
        try:
            if f.endswith('.py'):
                f = f[:-3]

            try:
                __import__(f, globals(), locals())
            except ImportError:
                if os.path.basename(f) == f:
                    raise

                os.chdir(os.path.join(wd, os.path.dirname(f)))
                __import__(os.path.basename(f), globals(), locals())

        except ImportError:
            log.exception("Unable to import module %r." % f)
            sys.exit(1)
        os.chdir(wd)

    return pants.engine.start

@command("A simple HTTP server.")
def http(global_options, arguments):
    parser = optparse.OptionParser(
                usage="%prog [global-options] http [options] [path]")

    parser.add_option("-b", "--bind", metavar="ADDRESS", dest="address",
                      default=":80", help="Bind the server to 'HOST', 'HOST:PORT', or 'unix:PATH'.")
    parser.add_option("--backlog", dest="backlog", type="int",
                      help="The maximum number of pending connections.")
    parser.add_option("-x", "--x-headers", action="store_true", dest="xhead",
                      default=False, help="Process X- headers received with requests.")

    parser.add_option("-i", "--index", metavar="FILE", dest="indices",
                      action="append", default=[], help="Serve files named FILE if available rather than a directory listing.")

    options, args = parser.parse_args(arguments)
    args = ''.join(args)

    # First, find the directory.
    path = os.path.realpath(args)
    if not os.path.exists(path) or not os.path.isdir(path):
        log.error("The provided path %r is not a directory or does not exist."
            % path)
        sys.exit(1)

    # Parse the address.
    address = parse_address(options.address)

    # Fix up the indices list.
    indices = options.indices
    if not indices:
        indices.extend(['index.html', 'index.htm'])

    # Import the necessary modules.
    from pants.contrib.http import HTTPServer
    from pants.contrib.web import FileServer

    # Create the server now. Exclude .py from the blacklist though, for now.
    fs = FileServer(path, blacklist=['.*\.pyc'], defaults=indices)
    server = HTTPServer(fs, xheaders=options.xhead)

    backlog = options.backlog if options.backlog else socket.SOMAXCONN

    # Start listening.
    server.listen(address[1], address[0], backlog)

    # Return a function that will start things up.
    return pants.engine.start

@command("Serve a WSGI application over an HTTP/1.1 server.")
def wsgi(global_options, arguments):
    parser = optparse.OptionParser(
                usage="%prog [global-options] wsgi [options] module:app")

    parser.add_option("-b", "--bind", metavar="ADDRESS", dest="address",
                      default=":80", help="Bind the server to 'HOST', 'HOST:PORT', or 'unix:PATH'.")
    parser.add_option("--backlog", dest="backlog", type="int",
                      help="The maximum number of pending connections.")
    parser.add_option("-x", "--x-headers", action="store_true", dest="xhead",
                      default=False, help="Process X- headers received with requests.")

    options, args = parser.parse_args(arguments)
    args = ''.join(args)

    # First, find our application.
    if not args:
        parser.parse_args(['--help'])

    if not ':' in args:
        log.error("You must specify a module and callable to host as a WSGI application.")
        sys.exit(1)

    module, _, call = args.partition(':')

    try:
        mod = __import__(module, globals(), locals())
    except ImportError:
        log.error("Unable to import the module %r." % module)
        sys.exit(1)

    if not hasattr(mod, call) or not callable(getattr(mod, call)):
        log.error("No such attribute %r in module %r." % (call, module))
        sys.exit(1)

    # Parse the address.
    address = parse_address(options.address)

    # Import the necessary modules.
    from pants.contrib.http import HTTPServer
    from pants.contrib.wsgi import WSGIConnector

    # Create the server now.
    connector = WSGIConnector(getattr(mod, call), global_options.debug)
    server = HTTPServer(connector, xheaders=options.xhead)

    backlog = options.backlog if options.backlog else socket.SOMAXCONN

    # Start listening.
    server.listen(address[1], address[0], backlog)

    # Return a function that will start things up.
    return pants.engine.start

###############################################################################
# Main
###############################################################################

if __name__ == '__main__':
    arguments = sys.argv[1:]

    # Find the command argument.
    for i in xrange(len(arguments)):
        if arguments[i].lower() in commands:
            command = arguments[i].lower()
            global_options = arguments[:i]
            arguments = arguments[i+1:]
            break
    else:
        command = None
        global_options = arguments
        arguments = []

    # Parse the global options.
    parser = NiceParser(version="Pants %s" % pants.__version__)

    parser.add_option("-d", "--debug", dest="debug", action="store_true",
                      default=False, help="Show DEBUG level log messages.")
    parser.add_option("-l", "--logfile", dest="logfile",
                      help="Log to the specified file, in addition to STDOUT.")

    group = optparse.OptionGroup(parser, "Profiling Options",
                   "The following options are useful for profiling your code.")

    group.add_option("-s", "--savestats", dest="statfile", default="-", metavar="FILE",
                     help="Save the results to the specified file, rather than displaying them.")
    group.add_option("-p", "--profile", dest="profile", default=False,
                     action="store_true", help="Run in profiling mode.")
    group.add_option("--profiler", dest="profiler", default="cprofile",
                     help="Name of the profiler to use, from: profile, cprofile")

    parser.add_option_group(group)

    if hasattr(os, 'getuid'):
        group = optparse.OptionGroup(parser, "User/Group ID Manipulation",
                    "These options, if used, will be acted upon immediately "
                    "before beginning the event loop and accept either "
                    "IDs or names.")

        group.add_option("-u", "--user", dest="user",
                         help="Switch to run as the specified user.")
        group.add_option("-g", "--group", dest="group",
                         help="Switch to run as the specified group.")

        parser.add_option_group(group)

    # Build the epilog text.
    epilog = ["", "Commands:"]
    for key in sorted(commands.keys()):
        desc, func = commands[key]
        epilog.append("  %-20s  %s" % (key, desc))
    epilog.append("")

    parser.epilog = '\r\n'.join(epilog)

    global_options, args = parser.parse_args(global_options)
    arguments.extend(args)
    del args

    # If there's no command, show help.
    if command is None:
        parser.parse_args(['--help'])

    # Setup logging.
    if sys.platform == 'win32':
        try:
            from colorama import init
            init()
        except ImportError:
            pass

    # Get a logger, and set the logging level.
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)

    # Build the console output for the log.
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if global_options.debug else logging.INFO)

    if sys.platform == 'win32':
        use_color = 'colorama' in sys.modules
    else:
        use_color = sys.stdout.isatty()

    if use_color:
        formatter = ColoredFormatter(
            u"\x1B[1;30m[%(levelname)-20s\x1B[1;30m]\x1B[0m %(asctime)s \x1B[1;37m%(message)s\x1B[0m",
            u"%H:%M:%S"
            )
    else:
        formatter = logging.Formatter(
            u"[%(levelname)-9s] %(asctime)s %(message)s",
            u"%H:%M:%S"
            )

    console.setFormatter(formatter)
    log.addHandler(console)

    # Setup file logging.
    if global_options.logfile:
        filelog = logging.FileHandler(global_options.logfile)

        formatter = logging.Formatter(
            u"%(asctime)s\t%(levelname)s\t%(message)s",
            u"%Y-%m-%d %H:%M:%S"
            )
        filelog.setFormatter(formatter)
        log.addHandler(filelog)

    # Run the command function and store the resulting function, which will be
    # used to actually start the event loop.
    real_starter = starter = commands[command][1](global_options, arguments)

    # Log the pants version
    log.log(PANTS, "Using Pants v%s" % pants.__version__)

    # Are we profiling?
    if global_options.profile:
        profiler = global_options.profiler.lower()
        pfile = global_options.statfile

        if profiler == 'cprofile':
            if pfile == '-':
                pfile = None

            import cProfile
            starter = functools.partial(cProfile.run, 'real_starter()', pfile)

        elif profiler == 'profile':
            if pfile == '-':
                pfile = None

            import profile
            starter = functools.partial(profile.run, 'real_starter()', pfile)

        elif profiler == 'hotshot':
            if pfile == '-':
                pfile = tempfile.mktemp()

            import hotshot
            profiler = hotshot.Profile(pfile)
            starter = functools.partial(profiler.runcall, real_starter)

        else:
            log.error("Invalid profiler. Profiler must be one of: cprofile, profile, hotshot")
            sys.exit(1)

    # Are we changing IDs?
    if hasattr(os, 'getuid'):
        # Do the group first because, otherwise, dropping the root uid would
        # make it impossible to then setgid.
        if global_options.group:
            try:
                import grp
            except ImportError:
                log.warning("Unable to import grp.")
                grp = None

            try:
                group = int(global_options.group)
            except ValueError:
                if grp is None:
                    log.error("Cannot lookup group name without grp.")
                    sys.exit(1)
                try:
                    group = grp.getgrnam(global_options.group)[2]
                except KeyError:
                    log.error("Invalid group name %r." % global_options.group)
                    sys.exit(1)

            # Now that we have a GID, try entering it.
            try:
                assert group
                os.setgid(group)
                assert os.getgid() == group
                if grp:
                    log.info("Assuming the GID %d (%s)." % (
                        group, grp.getgrgid(group)[0]))
                else:
                    log.info("Assuming the GID %d." % group)
            except (AssertionError, OSError):
                log.error("Unable to assume the GID %d." % group)
                sys.exit(1)

        if global_options.user:
            try:
                import pwd
            except ImportError:
                log.warning("Unable to import pwd.")
                pwd = None

            try:
                user = int(global_options.user)
            except ValueError:
                if pwd is None:
                    log.error("Cannot lookup username without pwd.")
                    sys.exit(1)
                try:
                    user = pwd.getpwnam(global_options.user)[2]
                except KeyError:
                    log.error("Invalid username %r." % global_options.user)
                    sys.exit(1)

            # Now that we have a UID, try entering it.
            try:
                assert user
                os.setuid(user)
                assert os.getuid() == user
                if pwd:
                    log.info("Assuming the UID %d (%s)." % (
                        user, pwd.getpwuid(user)[0]))
                else:
                    log.info("Assuming the UID %d." % user)
            except (AssertionError, OSError):
                log.error("Unable to assume the UID %d." % user)
                sys.exit(1)

    # Debug Information
    if global_options.debug:
        for k,v in pants.engine._channels.iteritems():
            if not v.listening:
                continue

            addr = v.local_addr
            if addr is None:
                continue

            if isinstance(addr, tuple):
                if addr[0] == '0.0.0.0' or addr[0] == '':
                    addr = 'port %d' % addr[1]
                else:
                    addr = '%s:%d' % addr
            elif isinstance(addr, basestring):
                addr = 'unix:%s' % addr
            else:
                addr = str(addr)

            log.debug('%s listening on %s' % (v.__class__.__name__, addr))

    # Now that we're set up, run it.
    starter()

    # Now, finish up.
    if global_options.profile and global_options.profiler.lower() == 'hotshot'\
            and global_options.statfile == '-':
        import hotshot.stats
        stats = hotshot.stats.load(pfile)

        stats.sort_stats('name').print_stats()

    # Close up the logs.
    logging.shutdown()
