import threading
import unittest

import pants

class PantsTestCase(unittest.TestCase):
    def setUp(self):
        self._engine_thread = threading.Thread(target=pants.engine.start)
        self._engine_thread.start()

    def tearDown(self):
        pants.engine.stop()
        self._engine_thread.join(1.0)
