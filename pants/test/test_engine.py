import unittest

from pants.engine import Engine

class TestEngine(unittest.TestCase):
    def test_engine_global_instance(self):
        engine1 = Engine.instance()
        engine2 = Engine.instance()

        self.assertTrue(engine1 is engine2)

    def test_engine_local_instances(self):
        engine1 = Engine()
        engine2 = Engine()

        self.assertFalse(engine1 is engine2)
