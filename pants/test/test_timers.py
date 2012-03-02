import time
import unittest

import pants

class TestTimers(unittest.TestCase):
    def setUp(self):
        self.times_called = []
        pants.engine._callbacks = []
        pants.engine._deferreds = []

    def timer(self):
        self.times_called.append(time.time())

    def test_callback(self):
        pants.engine.callback(self.timer)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 1)

    def test_callback_cancel(self):
        cancel_callback = pants.engine.callback(self.timer)
        cancel_callback()
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 0)

    def test_loop(self):
        pants.engine.loop(self.timer)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 3)

    def test_loop_cancel(self):
        cancel_loop = pants.engine.loop(self.timer)
        pants.engine.poll(0.01)
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 2)
        cancel_loop()
        pants.engine.poll(0.01)
        self.assertEquals(len(self.times_called), 2)

    def test_defer(self):
        expected_time = time.time() + 0.01
        pants.engine.defer(0.01, self.timer)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 1)
        self.assertLess(abs(expected_time - self.times_called[0]), 0.01)

    def test_defer_cancel(self):
        cancel_defer = pants.engine.defer(0.01, self.timer)
        cancel_defer()
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 0)

    def test_defer_with_zero_delay(self):
        self.assertRaises(ValueError, pants.engine.defer, 0, self.timer)

    def test_defer_with_negative_delay(self):
        self.assertRaises(ValueError, pants.engine.defer, -1.0, self.timer)

    def test_cycle(self):
        expected_times = [time.time() + 0.01, time.time() + 0.02, time.time() + 0.03]
        pants.engine.cycle(0.01, self.timer)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 3)
        self.assertLess(abs(expected_times[0] - self.times_called[0]), 0.01)
        self.assertLess(abs(expected_times[1] - self.times_called[1]), 0.01)
        self.assertLess(abs(expected_times[2] - self.times_called[2]), 0.01)

    def test_cycle_cancel(self):
        expected_times = [time.time() + 0.01, time.time() + 0.02, time.time() + 0.03]
        cancel_cycle = pants.engine.cycle(0.01, self.timer)
        pants.engine.poll(0.2)
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 2)
        cancel_cycle()
        pants.engine.poll(0.2)
        self.assertEquals(len(self.times_called), 2)
        self.assertLess(abs(expected_times[0] - self.times_called[0]), 0.01)
        self.assertLess(abs(expected_times[1] - self.times_called[1]), 0.01)

    def test_cycle_with_zero_delay(self):
        self.assertRaises(ValueError, pants.engine.cycle, 0, self.timer)

    def test_cycle_with_negative_delay(self):
        self.assertRaises(ValueError, pants.engine.cycle, -1.0, self.timer)
