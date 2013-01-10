###############################################################################
#
# Copyright 2012 Pants Developers (see AUTHORS.txt)
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

import sys
import time
import unittest

from mock import MagicMock, call

from pants.engine import Engine

class TestTimers(unittest.TestCase):
    def setUp(self):
        self.times_called = []
        self.engine = Engine()

    def timer(self):
        self.times_called.append(self.engine.time)

    def test_callback(self):
        timer = MagicMock()
        self.engine.callback(timer)
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        timer.assert_called_once_with()

    def test_callback_cancel(self):
        timer = MagicMock()
        cancel_callback = self.engine.callback(timer)
        cancel_callback()
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        self.assertRaises(AssertionError, timer.assert_called_with)

    def test_loop(self):
        timer = MagicMock()
        self.engine.loop(timer)
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        timer.assert_has_calls([call() for _ in range(3)])

    def test_loop_cancel(self):
        timer = MagicMock()
        cancel_loop = self.engine.loop(timer)
        self.engine.poll(0.01)
        self.engine.poll(0.01)
        timer.assert_has_calls([call() for _ in range(2)])
        cancel_loop()
        self.engine.poll(0.01)
        timer.assert_has_calls([call() for _ in range(2)])

    def test_defer(self):
        self.engine.poll(0.01)
        timer = MagicMock(side_effect=self.timer)
        expected_time = self.engine.time + 0.01
        self.engine.defer(0.01, timer)
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        timer.assert_called_once_with()
        self.assertLess(abs(expected_time - self.times_called[0]), 0.01)

    def test_defer_cancel(self):
        timer = MagicMock()
        cancel_defer = self.engine.defer(0.01, timer)
        cancel_defer()
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        self.assertRaises(AssertionError, timer.assert_called_with)

    def test_cycle(self):
        self.engine.poll(0.01)
        timer = MagicMock(side_effect=self.timer)
        expected_times = [
            self.engine.time + 0.01,
            self.engine.time + 0.02,
            self.engine.time + 0.03
            ]
        self.engine.cycle(0.01, timer)
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        if sys.platform == "win32": self.engine.poll(0.02)  # See issue #40
        timer.assert_has_calls([call() for _ in range(3)])
        for i in range(3):
            self.assertLess(abs(expected_times[i] - self.times_called[i]), 0.01)

    def test_cycle_cancel(self):
        self.engine.poll(0.01)
        timer = MagicMock(side_effect=self.timer)
        expected_times = [
            self.engine.time + 0.01,
            self.engine.time + 0.02
            ]
        cancel_cycle = self.engine.cycle(0.01, timer)
        self.engine.poll(0.2)
        self.engine.poll(0.2)
        if sys.platform == "win32": self.engine.poll(0.02)  # See issue #40
        timer.assert_has_calls([call() for _ in range(2)])
        cancel_cycle()
        self.engine.poll(0.2)
        timer.assert_has_calls([call() for _ in range(2)])
        for i in range(2):
            self.assertLess(abs(expected_times[i] - self.times_called[i]), 0.01)
