# -*- coding: utf-8 -*-
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

###############################################################################
# Imports
###############################################################################

import json
try:
    import requests
except ImportError:
    requests = None

from pants.http import HTTPServer
from pants.engine import Engine

from pants.test._pants_util import *

###############################################################################
# The Test Case Base
###############################################################################

class HTTPTestCase(PantsTestCase):
    def request_handler(self, request):
        raise NotImplementedError

    def setUp(self):
        engine = Engine.instance()
        self.server = HTTPServer(self.request_handler, engine=engine)
        self.server.listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self, engine)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

###############################################################################
# The Cases
###############################################################################

@unittest.skipIf(requests is None, "requests library not installed")
class BasicTest(HTTPTestCase):
    def request_handler(self, request):
        request.send_response("Hello, World!")

    def test_basic(self):
        response = requests.get("http://127.0.0.1:4040/", timeout=0.5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Hello, World!")

@unittest.skipIf(requests is None, "requests library not installed")
class ExceptionTest(HTTPTestCase):
    def request_handler(self, request):
        print pie

    def test_exception(self):
        response = requests.get("http://127.0.0.1:4040/", timeout=0.5)
        self.assertEqual(response.status_code, 500)

@unittest.skipIf(requests is None, "requests library not installed")
class CookieTest(HTTPTestCase):
    def request_handler(self, request):
        for key in request.cookies:
            val = request.cookies[key].value
            request.cookies_out[val] = key

        request.send_response("Hello, Cookies!")

    def test_cookies(self):
        response = requests.get("http://127.0.0.1:4040/",
                                cookies={"foo": "bar"}, timeout=0.5)
        self.assertEqual(response.cookies["bar"], "foo")

@unittest.skipIf(requests is None, "requests library not installed")
class SecureCookieTest(HTTPTestCase):
    def request_handler(self, request):
        request.set_secure_cookie("foo", "bar")
        request.set_secure_cookie("baz", u"こんにちは！")
        request.set_secure_cookie("what", [True, False, None])
        request.set_secure_cookie("pizza", "tasty", secure=True)
        request.send_response("Hello, Cookies!")

    def other_handler(self, request):
        if request.get_secure_cookie("foo") == "bar" and \
                request.get_secure_cookie("baz") == u"こんにちは！" and \
                request.get_secure_cookie("what") == [True, False, None] and \
                not request.get_secure_cookie("pizza"):
            request.send_response("Okay.")
        else:
            request.send_response("Bad.", 400)

    def test_cookies(self):
        response = requests.get("http://127.0.0.1:4040/", timeout=0.5)
        self.assertEqual(response.status_code, 200)

        self.server.request_handler = self.other_handler

        response = requests.get("http://127.0.0.1:4040/", cookies=response.cookies)
        self.assertEqual(response.status_code, 200)

@unittest.skipIf(requests is None, "requests library not installed")
class ResponseBody(HTTPTestCase):
    def request_handler(self, request):
        data = json.loads(request.body)
        request.send_response(json.dumps(list(reversed(data))))

    def test_body(self):
        response = requests.post("http://127.0.0.1:4040/", json.dumps(range(50)), timeout=0.5)
        data = json.loads(response.text)
        self.assertListEqual(data, range(49, -1, -1))
