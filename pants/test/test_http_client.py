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

import unittest
import json

from pants.http import HTTPClient
from pants.engine import Engine

from pants.test._pants_util import *

###############################################################################
# SSL Verification Check
###############################################################################

try:
    HTTPClient(verify_ssl=True)
    VERIFY_SSL = True
except RuntimeError:
    VERIFY_SSL = False

###############################################################################
# The Test Case Base
###############################################################################

class HTTPTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = Engine.instance()
        self.client = HTTPClient(self.on_response, self.on_headers, self.on_progress, self.on_ssl_error, self.on_error, engine=self.engine)

    def start(self, timeout=5.0):
        self._timeout = self.engine.defer(timeout, self.timeout)
        self.engine.start()

        self.assertTrue(self.got_response)
        self.assertTrue(self.response_valid)

    def timeout(self):
        self.stop()
        raise AssertionError("Timed out.")

    def stop(self):
        self._timeout()
        del self._timeout
        self.engine.stop()

    def tearDown(self):
        if self.client._stream:
            self.client._want_close = True
            self.client._no_process = True
            self.client._stream.close()
            self.client._stream = None
        del self.client
        del self.engine

    got_response = False
    response_valid = True

    def on_response(self, response):
        self.stop()
        self.got_response = True

    def on_headers(self, response):
        pass

    def on_progress(self, response, received, total):
        pass

    def on_ssl_error(self, response, cert, error):
        pass

    def on_error(self, response, error):
        pass

###############################################################################
# The Cases
###############################################################################

class GetTest(HTTPTestCase):
    def on_response(self, response):
        self.got_response = True
        self.stop()

    def test_get(self):
        self.client.get("http://httpbin.org/ip", {"foo": "bar"})
        self.start()


class PostTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        data = response.json
        if not data["form"]["foo"] == "bar":
            self.response_valid = False

    def test_post(self):
        self.client.post("http://httpbin.org/post", {"foo": "bar"})
        self.start()

    def test_multipart(self):
        self.got_response = False
        self.response_valid = True

        self.client.post("http://httpbin.org/post", {"foo": "bar"},
                         {"file": ("test.py", "whee")})
        self.start()


class HostChangeTest(HTTPTestCase):

    resp_count = 0

    def on_response(self, response):
        self.resp_count += 1
        if self.resp_count < 2:
            return

        self.stop()
        self.got_response = True

    def test_cookie(self):
        self.client.get("http://www.google.com/")
        self.client.get("http://httpbin.org/ip")
        self.start()


class TimeoutTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.response_valid = False

    def on_error(self, response, error):
        self.stop()
        self.got_response = True

    def test_timeout(self):
        with self.client.session(timeout=1) as ses:
            ses.get("http://httpbin.org/delay/3")
        self.start()


class BadHostTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()

    def on_error(self, response, error):
        self.got_response = True
        self.stop()

    def test_bad_host(self):
        self.client.get("http://www.python.rog/")
        self.start()



class BadPortTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()

    def on_error(self, response, error):
        self.got_response = True
        self.stop()

    def test_bad_port(self):
        self.client.get("http://httpbin.org:65432/")
        self.start()


class GzippedTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        data = response.json
        if not data["gzipped"] and \
                response.headers['Content-Encoding'] == 'gzip':
            self.response_valid = False

    def test_gzipped(self):
        self.client.get("http://httpbin.org/gzip")
        self.start()


class TeapotTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        if not response.status_code == 418:
            self.response_valid = False

    def test_teapot(self):
        self.client.get("http://httpbin.org/status/418")
        self.start()


class RedirectTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        if not len(response.history) == 3 or not response.path == "/get":
            self.response_valid = False

    def test_redirect(self):
        self.client.get("http://httpbin.org/redirect/3")
        self.start()


class RedirectLimitTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        if not (len(response.history) == 10 and response.status_code == 302):
            self.response_valid = False

    def test_limit(self):
        self.client.get("http://httpbin.org/redirect/12")
        self.start(10)


class RedirectRelativeTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        if not response.path == "/get":
            self.response_valid = False

    def test_relative(self):
        self.client.get("http://httpbin.org/relative-redirect/3")
        self.start()


class CookieTest(HTTPTestCase):

    resp_count = 0

    def on_response(self, response):
        self.resp_count += 1
        if self.resp_count < 2:
            return

        self.stop()
        self.got_response = True

        if not response.cookies["foo"].value == "bar":
            self.response_valid = False

    def test_cookie(self):
        self.client.get("http://httpbin.org/cookies/set/foo/bar")
        self.client.get("http://httpbin.org/cookies")
        self.start()


class AuthTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        if not response.status_code == 401:
            self.response_valid = False

    def test_auth(self):
        self.client.get("http://httpbin.org/basic-auth/user/passwd")
        self.start()


class DoAuthTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

        if not response.status_code == 200:
            self.response_valid = False

    def test_do_auth(self):
        with self.client.session(auth=("user", "passwd")) as ses:
            ses.get("http://httpbin.org/basic-auth/user/passwd")
        self.start()


class HTTPSTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

    def test_https(self):
        self.client.get("https://httpbin.org/ip")
        self.start()


@unittest.skipIf(not VERIFY_SSL, "Unable to verify SSL certificates without CA bundle. Install certifi and backports.ssl_match_hostname.")
class BadCertTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()

    def on_ssl_error(self, response, cert, error):
        self.stop()
        self.got_response = True

    def test_bad(self):
        with self.client.session(verify_ssl=True) as ses:
            ses.get("https://www.httpbin.org/ip")
        self.start()


@unittest.skipIf(not VERIFY_SSL, "Unable to verify SSL certificates without CA bundle. Install certifi and backports.ssl_match_hostname.")
class SSLOverrideTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

    def on_ssl_error(self, response, cert, error):
        return True

    def test_override(self):
        with self.client.session(verify_ssl=True) as ses:
            ses.get("https://www.httpbin.org/ip")
        self.start()


class ProgressTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()

    def on_progress(self, response, received, total):
        self.got_response = True

    def test_progress(self):
        self.client.get("http://httpbin.org/get")
        self.start()


class ForceURLEncodedTest(HTTPTestCase):
    def on_response(self, response):
        self.stop()
        self.got_response = True

    def test_force_urlencoded(self):
        self.client.post("http://httpbin.org/post",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.start()
