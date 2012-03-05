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

from pants.engine import Engine

try:
    from PySide.QtCore import QCoreApplication, QSocketNotifier, QTimer
except ImportError:
    from PyQt.QtCore import QCoreApplication, QSocketNotifier, QTimer

###############################################################################
# _Qt Class
###############################################################################

class _Qt(object):
    """
    A QSocketNotifier-based polling object.

    This caches events, waiting for the next call to poll, which should be
    called every loop by a QTimer.
    """
    def __init__(self):
        self._r = {}
        self._w = {}
        self._e = {}

        self._readable = set()
        self._writable = set()
        self._errored = set()

    def _read_event(self, fileno):
        self._readable.add(fileno)
        try:
            self._r[fileno].setEnabled(False)
        except KeyError:
            pass
        timer.setInterval(0)

    def _write_event(self, fileno):
        self._writable.add(fileno)
        try:
            self._w[fileno].setEnabled(False)
        except KeyError:
            pass
        timer.setInterval(0)

    def _error_event(self, fileno):
        self._errored.add(fileno)
        try:
            self._e[fileno].setEnabled(False)
        except KeyError:
            pass
        timer.setInterval(0)

    def add(self, fileno, events):
        if events & Engine.READ:
            self._r[fileno] = qs = QSocketNotifier(fileno,
                                        QSocketNotifier.Type.Read)
            qs.activated.connect(self._read_event)

        if events & Engine.WRITE:
            self._w[fileno] = qs = QSocketNotifier(fileno,
                                        QSocketNotifier.Type.Write)
            qs.activated.connect(self._write_event)

        if events & Engine.ERROR:
            self._e[fileno] = qs = QSocketNotifier(fileno,
                                        QSocketNotifier.Type.Exception)
            qs.activated.connect(self._error_event)

    def modify(self, fileno, events):
        if events & Engine.READ and not fileno in self._r:
            self._r[fileno] = qs = QSocketNotifier(fileno,
                                        QSocketNotifier.Type.Read)
            qs.activated.connect(self._read_event)

        elif not events & Engine.READ and fileno in self._r:
            self._r[fileno].setEnabled(False)
            del self._r[fileno]

        if events & Engine.WRITE and not fileno in self._w:
            self._w[fileno] = qs = QSocketNotifier(fileno,
                                        QSocketNotifier.Type.Write)
            qs.activated.connect(self._write_event)

        elif not events & Engine.WRITE and fileno in self._w:
            self._w[fileno].setEnabled(False)
            del self._w[fileno]

        if events & Engine.ERROR and not fileno in self._e:
            self._e[fileno] = qs = QSocketNotifier(fileno,
                                        QSocketNotifier.Type.Exception)
            qs.activated.connect(self._error_event)

        elif not events & Engine.ERROR and fileno in self._e:
            self._e[fileno].setEnabled(False)
            del self._e[fileno]

    def remove(self, fileno, events):
        if fileno in self._r:
            self._r[fileno].setEnabled(False)
            del self._r[fileno]
        if fileno in self._w:
            self._w[fileno].setEnabled(False)
            del self._w[fileno]
        if fileno in self._e:
            self._e[fileno].setEnabled(False)
            del self._e[fileno]

    def poll(self, timeout):
        events = {}

        for fileno in self._readable:
            events[fileno] = events.get(fileno, 0) | Engine.READ
            if fileno in self._r:
                self._r[fileno].setEnabled(True)

        for fileno in self._writable:
            events[fileno] = events.get(fileno, 0) | Engine.WRITE
            if fileno in self._w:
                self._w[fileno].setEnabled(True)

        for fileno in self._errored:
            events[fileno] = events.get(fileno, 0) | Engine.ERROR
            if fileno in self._e:
                self._e[fileno].setEnabled(True)

        self._readable.clear()
        self._writable.clear()
        self._errored.clear()

        return events

def do_poll():
    """
    Here, we run the Pants event loop. Then, we set the timer interval, either
    to the provided timeout, or for how long it would take to reach the
    earliest deferred event.
    """
    _engine.poll(0)

    if _engine._deferreds:
        timer.setInterval(min(1000 * (_engine._deferreds[0].end - _engine.time), _timeout))
    else:
        timer.setInterval(_timeout)

###############################################################################
# Installation Function
###############################################################################

timer = None
_timeout = 0.02
_engine = None

def install(app=None, timeout=0.02, engine=None):
    """
    Creates a :class:`~PySide.QtCore.QTimer` instance that will be triggered
    continuously to call :func:`Engine.poll() <pants.engine.Engine.poll>`,
    ensuring that Pants remains responsive.

    =========  ========  ============
    Argument   Default   Description
    =========  ========  ============
    app        None      *Optional.* The :class:`~PySide.QtCore.QCoreApplication` to attach to. If no application is provided, it will attempt to find an existing application in memory, or, failing that, create a new application instance.
    timeout    ``0.02``  *Optional.* The maximum time to wait, in seconds, before running :func:`Engine.poll() <pants.engine.Engine.poll>`.
    engine               *Optional.* The :class:`pants.engine.Engine` instance to use.
    =========  ========  ============
    """
    global timer
    global _timeout
    global _engine

    _engine = engine or Engine.instance()
    _engine._install_poller(_Qt())

    if app is None:
        app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    _timeout = timeout * 1000

    timer = QTimer(app)
    timer.timeout.connect(do_poll)
    timer.start(_timeout)
