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

import errno
import select
import time
import unittest

from mock import call, MagicMock

from pants.engine import Engine, _EPoll, _KQueue, _Select, _Timer

class TestEngine(unittest.TestCase):
    def test_engine_global_instance(self):
        engine1 = Engine.instance()
        engine2 = Engine.instance()

        self.assertTrue(engine1 is engine2)

    def test_engine_local_instances(self):
        engine1 = Engine()
        engine2 = Engine()

        self.assertFalse(engine1 is engine2)

class TestEngineStart(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def test_when_shutdown_is_true(self):
        self.engine._shutdown = True
        self.engine.start()
        self.assertFalse(self.engine._shutdown)

    def test_when_shutdown_is_false_and_running_is_true(self):
        self.engine._shutdown = False
        self.engine._running = True
        self.engine.start()
        self.assertFalse(self.engine._shutdown)
        self.assertTrue(self.engine._running)

    def test_when_engine_is_stopped_normally(self):
        def poll(engine):
            self.engine.stop()

        self.engine.poll = poll
        self.engine.start()
        self.assertFalse(self.engine._shutdown)
        self.assertFalse(self.engine._running)

    def test_when_poll_raises_systemexit(self):
        def poll(engine):
            raise SystemExit

        self.engine.poll = poll
        self.assertRaises(SystemExit, self.engine.start)
        self.assertFalse(self.engine._shutdown)
        self.assertFalse(self.engine._running)

    def test_when_poll_raises_exception(self):
        def poll(engine):
            raise Exception

        self.engine.poll = poll
        self.engine.start()
        self.assertFalse(self.engine._shutdown)
        self.assertFalse(self.engine._running)

class TestEngineStop(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def test_when_running(self):
        self.engine._shutdown = False
        self.engine._running = True
        self.engine.stop()
        self.assertTrue(self.engine._shutdown)

    def test_when_not_running(self):
        self.engine._shutdown = False
        self.engine._running = False
        self.engine.stop()
        self.assertFalse(self.engine._shutdown)

class TestEnginePoll(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def test_poll_updates_time(self):
        current_time = self.engine.latest_poll_time
        time.sleep(0.02)
        self.engine.poll(0.02)
        self.assertTrue(self.engine.latest_poll_time > current_time)

    def test_poll_executes_callbacks(self):
        callback = MagicMock()
        callback.function = MagicMock()
        callback.requeue = False
        self.engine._callbacks.append(callback)
        self.engine.poll(0.02)
        callback.function.assert_called_once_with()
        self.assertTrue(len(self.engine._callbacks) == 0)

    def test_callback_exception_doesnt_break_poll(self):
        callback = MagicMock()
        callback.function = MagicMock(side_effect=Exception)
        callback.requeue = False
        self.engine._callbacks.append(callback)
        try:
            self.engine.poll(0.02)
        except Exception:
            self.fail("Exception in callback function was not caught.")

    def test_keyboardinterrupt_during_callback_processing_is_raised(self):
        callback = MagicMock()
        callback.function = MagicMock(side_effect=KeyboardInterrupt)
        callback.requeue = False
        self.engine._callbacks.append(callback)
        self.assertRaises(KeyboardInterrupt, self.engine.poll, 0.02)

    def test_systemexit_during_callback_processing_is_raised(self):
        callback = MagicMock()
        callback.function = MagicMock(side_effect=SystemExit)
        callback.requeue = False
        self.engine._callbacks.append(callback)
        self.assertRaises(SystemExit, self.engine.poll, 0.02)

    def test_poll_requeues_loops(self):
        loop = MagicMock()
        loop.function = MagicMock()
        loop.requeue = True
        self.engine._callbacks.append(loop)
        self.engine.poll(0.02)
        self.assertTrue(loop in self.engine._callbacks)

    def test_poll_executes_deferreds(self):
        defer = MagicMock()
        defer.function = MagicMock()
        defer.requeue = False
        defer.end = self.engine.latest_poll_time - 1
        self.engine._deferreds.append(defer)
        self.engine.poll(0.02)
        defer.function.assert_called_once_with()

    def test_deferred_exception_doesnt_break_poll(self):
        defer = MagicMock()
        defer.function = MagicMock()
        defer.requeue = False
        defer.end = self.engine.latest_poll_time - 1
        self.engine._deferreds.append(defer)
        try:
            self.engine.poll(0.02)
        except Exception:
            self.fail("Exception in deferred was not caught.")

    def test_keyboardinterrupt_during_deferred_processing_is_raised(self):
        defer = MagicMock()
        defer.function = MagicMock(side_effect=KeyboardInterrupt)
        defer.requeue = False
        defer.end = self.engine.latest_poll_time - 1
        self.engine._deferreds.append(defer)
        self.assertRaises(KeyboardInterrupt, self.engine.poll, 0.02)

    def test_systemexit_during_deferred_processing_is_raised(self):
        defer = MagicMock()
        defer.function = MagicMock(side_effect=SystemExit)
        defer.requeue = False
        defer.end = self.engine.latest_poll_time - 1
        self.engine._deferreds.append(defer)
        self.assertRaises(SystemExit, self.engine.poll, 0.02)

    def test_poll_requeues_deferreds(self):
        cycle = MagicMock()
        cycle.function = MagicMock()
        cycle.requeue = True
        cycle.end = self.engine.latest_poll_time - 1
        cycle.delay = 10
        self.engine._deferreds.append(cycle)
        self.engine.poll(0.02)
        self.assertTrue(cycle in self.engine._deferreds)

    def test_poll_returns_if_timer_shuts_down_engine(self):
        # Pretty ugly way of testing this, to be honest.
        self.engine._poller.poll = MagicMock()
        self.engine._channels = {1: None}
        self.engine.callback(self.engine.stop)
        self.engine.poll(0.02)
        self.assertRaises(AssertionError, self.engine._poller.poll.assert_called_once_with)

    def test_poll_sleeps_for_poll_timeout(self):
        before = time.time()
        self.engine.poll(0.225)
        after = time.time()
        # It's never exactly the timeout length, but it gets very close.
        self.assertTrue((after - before) > 0.22)

    def test_poll_sleeps_until_next_deferred(self):
        defer = MagicMock()
        defer.function = MagicMock()
        defer.requeue = False
        self.engine._deferreds.append(defer)
        before = time.time()
        defer.end = before + 0.225
        self.engine.poll(1)
        after = time.time()
        # Again, never going to be exact.
        self.assertTrue((after - before) < 0.25)

    def test_poller_successful(self):
        self.engine._channels = {1: None}
        self.engine._poller.poll = MagicMock()
        self.engine.poll(0.02)
        self.engine._poller.poll.assert_called_once_with(0.02)

    def test_poller_raises_EINTR(self):
        self.engine._channels = {1: None}
        self.engine._poller.poll = MagicMock(side_effect=Exception(errno.EINTR))
        try:
            self.engine.poll(0.02)
        except Exception as err:
            if err.args[0] == errno.EINTR:
                self.fail("EINTR during polling was not caught.")

    def test_poller_raises_unknown(self):
        self.engine._channels = {1: None}
        self.engine._poller.poll = MagicMock(side_effect=Exception)
        self.assertRaises(Exception, self.engine.poll, 0.02)

    def test_poll_processes_events(self):
        channel = MagicMock()
        channel._handle_events = MagicMock()
        self.engine._channels = {1: channel}
        self.engine._poller.poll = MagicMock(return_value={1:Engine.ALL_EVENTS})
        self.engine.poll(0.02)
        channel._handle_events.assert_called_once_with(Engine.ALL_EVENTS)

    def test_event_processing_error_doesnt_break_poll(self):
        channel = MagicMock()
        channel._handle_events = MagicMock(side_effect=Exception)
        self.engine._channels = {1: channel}
        self.engine._poller.poll = MagicMock(return_value={1:Engine.ALL_EVENTS})
        try:
            self.engine.poll(0.02)
        except Exception:
            self.fail("Exception raised during event processing was not caught.")

    def test_keyboardinterrupt_during_event_processing_is_raised(self):
        channel = MagicMock()
        channel._handle_events = MagicMock(side_effect=KeyboardInterrupt)
        self.engine._channels = {1: channel}
        self.engine._poller.poll = MagicMock(return_value={1:Engine.ALL_EVENTS})
        self.assertRaises(KeyboardInterrupt, self.engine.poll, 0.02)

    def test_systemexit_during_event_processing_is_raised(self):
        channel = MagicMock()
        channel._handle_events = MagicMock(side_effect=SystemExit)
        self.engine._channels = {1: channel}
        self.engine._poller.poll = MagicMock(return_value={1:Engine.ALL_EVENTS})
        self.assertRaises(SystemExit, self.engine.poll, 0.02)

class TestEngineTimers(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def test_callback_added(self):
        timer = self.engine.callback(MagicMock())
        self.assertTrue(timer in self.engine._callbacks)

    def test_loop_added(self):
        timer = self.engine.loop(MagicMock())
        self.assertTrue(timer in self.engine._callbacks)

    def test_deferred_added(self):
        timer = self.engine.defer(10, MagicMock())
        self.assertTrue(timer in self.engine._deferreds)

    def test_deferred_with_zero_delay(self):
        self.assertRaises(ValueError, self.engine.defer, 0, MagicMock())

    def test_deferred_with_negative_delay(self):
        self.assertRaises(ValueError, self.engine.defer, -1, MagicMock())

    def test_cycle_added(self):
        timer = self.engine.cycle(10, MagicMock())
        self.assertTrue(timer in self.engine._deferreds)

    def test_cycle_with_zero_delay(self):
        self.assertRaises(ValueError, self.engine.cycle, 0, MagicMock())

    def test_cycle_with_negative_delay(self):
        self.assertRaises(ValueError, self.engine.cycle, -1, MagicMock())

    def test_remove_timer_with_no_end(self):
        timer = self.engine.callback(MagicMock())
        self.engine._remove_timer(timer)

    def test_remove_nonexistent_timer_with_no_end(self):
        timer = MagicMock()
        timer.end = None
        self.engine._remove_timer(timer)

    def test_remove_timer_with_end(self):
        timer = self.engine.defer(10, MagicMock())
        self.engine._remove_timer(timer)

    def test_remove_nonexistent_timer_with_end(self):
        timer = MagicMock()
        timer.end = 1
        self.engine._remove_timer(timer)

class TestEngineAddChannel(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()
        self.poller = MagicMock()
        self.poller.add = MagicMock()
        self.engine._poller = self.poller
        self.channel = MagicMock()
        self.channel.fileno = "foo"
        self.channel._events = "bar"

    def test_channel_is_added_to_engine(self):
        self.engine.add_channel(self.channel)
        self.assertTrue(self.channel.fileno in self.engine._channels)
        self.assertEqual(self.engine._channels[self.channel.fileno], self.channel)

    def test_channel_is_added_to_poller(self):
        self.engine.add_channel(self.channel)
        self.poller.add.assert_called_once_with(self.channel.fileno, self.channel._events)

class TestEngineModifyChannel(unittest.TestCase):
    def test_channel_is_modified_on_poller(self):
        engine = Engine()
        channel = MagicMock()
        channel.fileno = "foo"
        channel._events = "bar"
        engine._poller.modify = MagicMock()
        engine.modify_channel(channel)
        engine._poller.modify.assert_called_once_with(channel.fileno, channel._events)

class TestEngineRemoveChannel(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()
        self.poller = MagicMock()
        self.poller.remove = MagicMock()
        self.engine._poller = self.poller
        self.channel = MagicMock()
        self.channel.fileno = "foo"
        self.channel._events = "bar"
        self.engine._channels[self.channel.fileno] = self.channel

    def test_channel_is_removed_from_engine(self):
        self.engine.remove_channel(self.channel)
        self.assertFalse(self.channel.fileno in self.engine._channels)

    def test_channel_is_removed_from_poller(self):
        self.engine.remove_channel(self.channel)
        self.poller.remove.assert_called_once_with(self.channel.fileno, self.channel._events)

    def test_removing_channel_from_poller_raises_IOError(self):
        self.poller.remove = MagicMock(side_effect=IOError())
        self.engine.remove_channel(self.channel)
        self.poller.remove.assert_called_once_with(self.channel.fileno, self.channel._events)

    def test_removing_channel_from_poller_raises_OSError(self):
        self.poller.remove = MagicMock(side_effect=OSError())
        self.engine.remove_channel(self.channel)
        self.poller.remove.assert_called_once_with(self.channel.fileno, self.channel._events)

    def test_removing_channel_from_poller_raises_unknown(self):
        self.poller.remove = MagicMock(side_effect=Exception())
        self.assertRaises(Exception, self.engine.remove_channel, self.channel)
        self.poller.remove.assert_called_once_with(self.channel.fileno, self.channel._events)

class TestEngineInstallPoller(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def test_custom_poller(self):
        poller = MagicMock()
        self.engine._poller = None
        self.engine._channels = {}
        self.engine._install_poller(poller)
        self.assertTrue(self.engine._poller is poller)

    @unittest.skip("Not yet implemented.")
    def test_custom_poller_with_existing_channels(self):
        self.fail("Not yet implemented.")

    @unittest.skip("Not yet implemented.")
    def test_custom_poller_with_existing_channels_and_poller(self):
        self.fail("Not yet implemented.")

    @unittest.skip("Not yet implemented.")
    @unittest.skipUnless(hasattr(select, "epoll"), "epoll-specific functionality.")
    def test_defaulting_to_epoll(self):
        self.fail("Not yet implemented.")

    @unittest.skip("Not yet implemented.")
    @unittest.skipIf(hasattr(select, "epoll"), "kqueue-specific functionality.")
    @unittest.skipUnless(hasattr(select, "kqueue"), "kqueue-specific functionality.")
    def test_defaulting_to_kqueue(self):
        self.fail("Not yet implemented.")

    @unittest.skip("Not yet implemented.")
    @unittest.skipIf(hasattr(select, "epoll"), "select-specific functionality.")
    @unittest.skipIf(hasattr(select, "kqueue"), "select-specific functionality.")
    def test_defaulting_to_select(self):
        self.fail("Not yet implemented.")

@unittest.skipUnless(hasattr(select, "epoll"), "epoll-specific functionality.")
class TestEpoll(unittest.TestCase):
    def setUp(self):
        self.poller = _EPoll()
        self.epoll = MagicMock()
        self.epoll.register = MagicMock()
        self.epoll.modify = MagicMock()
        self.epoll.unregister = MagicMock()
        self.epoll.poll = MagicMock()
        self.poller._epoll = self.epoll
        self.fileno = "foo"
        self.events = "bar"

    def test_epoll_add(self):
        self.poller.add(self.fileno, self.events)
        self.epoll.register.assert_called_once_with(self.fileno, self.events)

    def test_epoll_modify(self):
        self.poller.modify(self.fileno, self.events)
        self.epoll.modify.assert_called_once_with(self.fileno, self.events)

    def test_epoll_remove(self):
        self.poller.remove(self.fileno, self.events)
        self.epoll.unregister.assert_called_once_with(self.fileno, self.events)

    def test_epoll_poll(self):
        timeout = 10
        ret = self.poller.poll(timeout)
        self.assertTrue(isinstance(ret, dict))
        self.epoll.poll.assert_called_once_with(timeout)

@unittest.skip("Not yet implemented.")
@unittest.skipUnless(hasattr(select, "kqueue"), "kqueue-specific functionality.")
class TestKQueue(unittest.TestCase):
    pass

class TestSelect(unittest.TestCase):
    def setUp(self):
        self.poller = _Select()
        self.fileno = "foo"
        # Beware: here be monkey-patching.
        self.real_select = select.select
        self.fake_select = MagicMock(return_value=([], [], []))
        select.select = self.fake_select

    def tearDown(self):
        select.select = self.real_select

    def test_select_add_all_events(self):
        self.poller.add(self.fileno, Engine.ALL_EVENTS)
        self.assertTrue(self.fileno in self.poller._r)
        self.assertTrue(self.fileno in self.poller._w)
        self.assertTrue(self.fileno in self.poller._e)

    def test_select_add_no_events(self):
        self.poller.add(self.fileno, Engine.NONE)
        self.assertFalse(self.fileno in self.poller._r)
        self.assertFalse(self.fileno in self.poller._w)
        self.assertFalse(self.fileno in self.poller._e)

    def test_select_add_one_event(self):
        self.poller.add(self.fileno, Engine.WRITE)
        self.assertFalse(self.fileno in self.poller._r)
        self.assertTrue(self.fileno in self.poller._w)
        self.assertFalse(self.fileno in self.poller._e)

    def test_select_add_doesnt_erase_previous_events(self):
        self.poller.add(self.fileno, Engine.READ)
        self.assertTrue(self.fileno in self.poller._r)
        self.assertFalse(self.fileno in self.poller._w)
        self.assertFalse(self.fileno in self.poller._e)
        self.poller.add(self.fileno, Engine.WRITE)
        self.assertTrue(self.fileno in self.poller._r)
        self.assertTrue(self.fileno in self.poller._w)
        self.assertFalse(self.fileno in self.poller._e)

    def test_select_modify(self):
        self.poller.remove = MagicMock()
        self.poller.add = MagicMock()
        self.poller.modify(self.fileno, Engine.ALL_EVENTS)
        self.poller.remove.assert_called_once_with(self.fileno, Engine.ALL_EVENTS)
        self.poller.add.assert_called_once_with(self.fileno, Engine.ALL_EVENTS)

    def test_select_remove(self):
        self.poller.add(self.fileno, Engine.ALL_EVENTS)
        # Remember, remove completely deregisters the fileno, it doesn't
        # remove individual events.
        self.poller.remove(self.fileno, Engine.NONE)
        self.assertFalse(self.fileno in self.poller._r)
        self.assertFalse(self.fileno in self.poller._w)
        self.assertFalse(self.fileno in self.poller._e)

    def test_select_poll(self):
        timeout = 10
        args = (self.poller._r, self.poller._w, self.poller._e, timeout)
        ret = self.poller.poll(timeout)
        self.assertTrue(isinstance(ret, dict))
        self.fake_select.assert_called_once_with(*args)

class TestTimer(unittest.TestCase):
    def test_calling_timer_calls_cancel(self):
        timer = _Timer(None, None, None)
        timer.cancel = MagicMock()
        timer()
        timer.cancel.assert_called_once_with()

    def test_comparing_two_timers_compares_end(self):
        timer1 = _Timer(None, None, None, end=1)
        timer2 = _Timer(None, None, None, end=2)
        self.assertTrue(timer2 > timer1)
        self.assertTrue(timer1 < timer2)

    def test_cancelling_timer_calls_engine_remove_timer(self):
        engine = Engine()
        engine._remove_timer = MagicMock()
        timer = _Timer(engine, None, None)
        timer.cancel()
        engine._remove_timer.assert_called_once_with(timer)
