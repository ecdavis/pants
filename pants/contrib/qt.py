###############################################################################
#
# Copyright 2011 Pants (see AUTHORS.txt)
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

    def _write_event(self, fileno):
        self._writable.add(fileno)
        try:
            self._w[fileno].setEnabled(False)
        except KeyError:
            pass

    def _error_event(self, fileno):
        self._errored.add(fileno)
        try:
            self._e[fileno].setEnabled(False)
        except KeyError:
            pass

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

    def remove(self, fileno):
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


###############################################################################
# Installation Function
###############################################################################

timer = None

def install(app=None, timeout=0.02):
    """
    Sets up the timer. This isn't necessary if you're going to be calling
    poll yourself. (And, if you ARE going to be calling poll yourself: why?)

    Args:
        app: The QApplication to attach to. If None, it will attempt to find
            the app or, failing that, it will create a new QCoreApplication
            instance.
        timeout: The length of time, in seconds, to wait between each call to
            the engine's poll function.
    """
    global timer

    Engine.instance()._install_poller(_Qt())

    if app is None:
        app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    timer = QTimer(app)
    timer.timeout.connect(functools.partial(Engine.instance().poll, 0))
    timer.start(timeout * 1000)
