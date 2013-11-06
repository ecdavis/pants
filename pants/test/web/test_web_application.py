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
"""
Tests for pants.web.Application.
"""

###############################################################################
# Imports
###############################################################################

try:
    import requests
except ImportError:
    requests = None

from mock import MagicMock

from pants.http import HTTPServer, HTTPRequest
from pants.engine import Engine
from pants.web import Application, url_for, error, abort, redirect

from pants.test._pants_util import *

###############################################################################
# Helper
###############################################################################

class RequestContext(object):
    def __init__(self, app, url='/', method='GET', protocol='HTTP/1.1',
                 headers=None, scheme='http', remote_address=("127.0.0.1", 99)):

        connection = MagicMock()
        connection.server = MagicMock()
        connection.server.xheaders = False
        connection.server.cookie_secret = "1234567890"
        connection.remote_address = remote_address

        connection.write = MagicMock()
        connection.finish = MagicMock()

        self.request = HTTPRequest(connection, method, url, protocol, headers, scheme)
        self.request.auto_finish = True

        self.app = app

        self.stack = []

        with self:
            self.result = self.app.route_request(self.request)

    def __enter__(self):
        self.stack.append((Application.current_app, self.app.request))
        Application.current_app = self.app
        self.app.request = self.request

    def __exit__(self, exc_type, exc_val, exc_tb):
        Application.current_app, self.app.request = self.stack.pop()


###############################################################################
# The Test Case Base
###############################################################################

@unittest.skipIf(requests is None, "requests is not installed")
class AppTestCase(PantsTestCase):
    def init_app(self, app):
        raise NotImplementedError

    def setUp(self):
        self.app = Application()
        self.init_app(self.app)

        engine = Engine.instance()
        self.server = HTTPServer(self.app, engine=engine)
        self.server.listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self, engine)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

###############################################################################
# url_for
###############################################################################

class TestUrlFor(AppTestCase):
    def init_app(self, app):
        @app.route("/")
        def index(request):
            return url_for('index')

        @app.route("/external")
        def external(request):
            return url_for('index', _external=True)

        @app.route("test.example.com/")
        def other_domain(request):
            return None

        @app.route("/domain")
        def domain(request):
            return url_for('other_domain')

        @app.route("/scheme")
        def scheme(request):
            return url_for('index', _scheme="ws")

        @app.route("/same_scheme")
        def same_scheme(request):
            return url_for('index', _scheme='http')

        @app.route("/bad")
        def bad(request):
            return url_for('bad_test')

        @app.route("/args/<var>/")
        def args(request, var):
            pass


    def test_basic(self):
        for url in ("/", "/external", "/test/pants"):
            with RequestContext(self.app, url):
                self.assertEqual(url_for('index'), '/')

        with RequestContext(self.app, headers={'Host': 'test.example.com'}):
            self.assertEqual(url_for('other_domain'), '/')

        with RequestContext(self.app):
            self.assertEqual(url_for('other_domain'), 'http://test.example.com/')

    def test_external(self):
        with RequestContext(self.app):
            self.assertEqual(
                url_for('index', _external=True),
                'http://127.0.0.1/'
            )

            self.assertEqual(
                url_for('other_domain'), 'http://test.example.com/'
            )

        with RequestContext(self.app, headers={'Host': 'www.example.com'}):
            self.assertEqual(
                url_for('scheme', _external=True),
                'http://www.example.com/scheme'
            )

        with RequestContext(self.app, headers={'Host': 'blah:1234'}):
            self.assertEqual(
                url_for('bad', _external=True),
                'http://blah:1234/bad'
            )

    def test_arguments(self):
        with RequestContext(self.app):
            self.assertEqual(url_for('index', test=True), '/?test=True')
            self.assertEqual(url_for('args', 'pie'), '/args/pie/')
            self.assertEqual(url_for('args', var='pie'), '/args/pie/')
            self.assertEqual(
                url_for('args', 'pie', test=True),
                '/args/pie/?test=True'
            )
            with self.assertRaises(ValueError):
                url_for('index', 32, 84)

    def test_domain(self):
        response = requests.get("http://127.0.0.1:4040/domain", timeout=0.5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "http://test.example.com/")

    def test_scheme(self):
        response = requests.get("http://127.0.0.1:4040/scheme", timeout=0.5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "ws://127.0.0.1:4040/")

    def test_same_scheme(self):
        response = requests.get("http://127.0.0.1:4040/same_scheme", timeout=0.5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "/")

    def test_bad(self):
        response = requests.get("http://127.0.0.1:4040/bad", timeout=0.5)
        self.assertEqual(response.status_code, 500)

    def test_context(self):
        with self.assertRaises(RuntimeError):
            url_for('index')
