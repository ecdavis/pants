import time
import unittest

import pants

class TestTimers(unittest.TestCase):
    def setUp(self):
        self.times_called = []

    def timer(self):
        self.times_called.append(time.time())

    def test_callback(self):
        pants.callback(self.timer)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 1)

    def test_loop(self):
        pants.loop(self.timer)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 3)

    def test_defer(self):
        expected_time = time.time() + 0.01
        pants.defer(0.01, self.timer)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 1)
        self.assertLess(abs(expected_time - self.times_called[0]), 0.01)

    def test_defer_with_zero_delay(self):
        self.assertRaises(ValueError, pants.defer, 0, self.timer)

    def test_defer_with_negative_delay(self):
        self.assertRaises(ValueError, pants.defer, -1.0, self.timer)

    def test_cycle(self):
        expected_times = [time.time() + 0.01, time.time() + 0.02, time.time() + 0.03]
        pants.cycle(0.01, self.timer)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 3)
        self.assertLess(abs(expected_times[0] - self.times_called[0]), 0.01)
        self.assertLess(abs(expected_times[1] - self.times_called[1]), 0.01)
        self.assertLess(abs(expected_times[2] - self.times_called[2]), 0.01)

    def test_cycle_with_zero_delay(self):
        self.assertRaises(ValueError, pants.cycle, 0, self.timer)

    def test_cycle_with_negative_delay(self):
        self.assertRaises(ValueError, pants.cycle, -1.0, self.timer)
