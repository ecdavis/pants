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
"""
Note: These tests were adapted from https://github.com/jonashaag/WSGITest
"""

###############################################################################
# Imports
###############################################################################

try:
    import requests
except ImportError:
    requests = None

import pprint

from pants.http import HTTPServer
from pants.web import WSGIConnector

from pants.test._pants_util import *

###############################################################################
# The Test Case Base
###############################################################################

@unittest.skipIf(requests is None, "requests library not installed")
class WSGITestCase(PantsTestCase):
    def application(self, env, start_response):
        raise NotImplementedError

    def setUp(self):
        engine = Engine.instance()
        self.server = HTTPServer(WSGIConnector(self.application, debug=True), engine=engine)
        self.server.listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self, engine)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

class WSGIBodyTest(WSGITestCase):
    body = None
    headers = None
    status = None

    def request(self):
        return requests.get("http://127.0.0.1:4040/", timeout=0.5)

    def test_thing(self):
        response = self.request()

        if self.body is not None:
            self.assertEqual(response.text, self.body)

        if self.status is not None:
            self.assertEqual(response.status_code, self.status)

        if self.headers is not None:
            for k,v in self.headers:
                self.assertEqual(response.headers[k], v)

class WSGIServerTest(WSGITestCase):
    def setUp(self):
        WSGITestCase.setUp(self)
        self.passed = True

    def logic(self, env, start_response):
        pass

    def application(self, env, start_response):
        try:
            self.logic(env, start_response)
        except AssertionError as err:
            print err
            print ""
            self.passed = False

        if not self.passed:
            pprint.pprint(env)

        start_response('200 OK', [])
        return []

    def request(self):
        requests.get("http://127.0.0.1:4040/", timeout=0.5)

    def test_thing(self):
        self.request()
        self.assertTrue(self.passed)

###############################################################################
# The Cases
###############################################################################

class EmptyHeader(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK', [])
        return ['hello']

    status = 200
    body = "hello"


class ContentLength(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK', [('Content-Length', 5)])
        return ['hello']

    status = 200
    body = "hello"


class TooFewArguments(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK')
        return []

    status = 500


class TooManyArguments(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK', [], 42, 38)
        return []

    status = 500


class WrongType(WSGIBodyTest):
    def application(self, env, start_response):
        start_response(object(), [])
        return ['hello']

    status = 500


class WrongType2(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK', object())
        return ['hello']

    status = 500


class WrongReturnType(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK', [])
        return object()

    status = 500


class MultiStart(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 OK', [])
        start_response('200 OK', [])
        return ['hello']

    status = 500


###############################################################################
# Server Tests
###############################################################################

class TestGET(WSGIServerTest):
    def logic(self, env, start_response):
        self.assertEqual(env['REQUEST_METHOD'], 'GET')


class TestPOST(WSGIServerTest):
    def logic(self, env, start_response):
        self.assertEqual(env['REQUEST_METHOD'], 'POST')
        self.assertEqual(env['CONTENT_LENGTH'], 12)
        self.assertEqual(env['wsgi.input'].read(), 'Hello World!')

    def request(self):
        requests.post("http://127.0.0.1:4040/", data="Hello World!", timeout=0.5)


class TestQS(WSGIServerTest):
    def logic(self, env, start_response):
        self.assertIn(env['QUERY_STRING'], ('foo=bar&x=y', 'x=y&foo=bar'))

    def request(self):
        requests.get("http://127.0.0.1:4040/", params={'foo':'bar', 'x':'y'}, timeout=0.5)


class TestQSEmpty(WSGIServerTest):
    def logic(self, env, start_response):
        self.assertEqual(env['QUERY_STRING'], '')


class TestHeaderVars(WSGIServerTest):
    def logic(self, env, start_response):
        self.assertDictContainsSubset({
            'HTTP_X_HELLO_IAM_A_HEADER': '42,42',
            'HTTP_HEADER_TWICE': [1, 2],
            'HTTP_IGNORETHECASE_PLEAS_E': 'hello world!',
            'HTTP_MULTILINE_VALUE': 'foo 42 bar and \\r\\n so on'
        }, env)

    def request(self):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 4040))
        sock.sendall("\r\n".join([
            "GET /foo HTTP/1.1",
            "x-hello-iam-a-header: 42,42",
            "header-twice: 1",
            "IgNoREtheCAsE_pLeas-E: hello world!",
            "header-twice: 2",
            "multiline-value: foo 42",
            "\tbar and \\r\\n\t",
            "\tso",
            " on",
            ]) + "\r\n\r\n")

        sock.settimeout(0.5)
        try:
            sock.recv(4096)
            sock.close()
        except Exception:
            pass


class TestWSGIVars(WSGIServerTest):
    def logic(self, env, start_response):
        self.assertIsInstance(env['wsgi.version'], tuple)
        self.assertEqual(len(env['wsgi.version']), 2)
        self.assertEqual(env['wsgi.url_scheme'][:4], 'http')
        self.assertIsInstance(env['wsgi.multithread'], bool)
        self.assertIsInstance(env['wsgi.multiprocess'], bool)
        self.assertIsInstance(env['wsgi.run_once'], bool)


class TestPostBody(WSGIServerTest):
    def logic(self, env, start_response):
        inp = env['wsgi.input']
        ae = self.assertEqual

        ae(inp.read(1), 'H')
        ae(inp.readline(), 'ello\n')

        for line in inp:
            ae(line, 'World,\r\n')
            break

        ae(inp.read(4), '\twha')
        ae(inp.readlines(), ["t's\r\n", '\r\n', '\n', 'up?'])
        ae(inp.read(123), '')

    def request(self):
        requests.post('http://127.0.0.1:4040/', data="Hello\nWorld,\r\n\twhat's\r\n\r\n\nup?", timeout=0.5)


###############################################################################
# Body Tests
###############################################################################

class TestEmptyChunks(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 ok', [])
        yield 'he'
        yield ''
        yield 'llo'

    body = 'hello'


class TestEmptyChunks2(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 ok', [])
        return ['', '', 'hello']

    body = 'hello'


class TestError(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 ok', [])
        yield 'foo'
        spicy_pies # NameError
        yield 'bar'

    body = 'foo'


class TestStartResponseInThing(WSGIBodyTest):
    def application(self, env, start_response):
        x = False
        for item in ('hello ', 'wor', 'ld!'):
            if not x:
                x = True
                start_response('321 blah', [('Content-Length', '12')])
            yield item

    status = 321
    body = 'hello world!'
    headers = [('Content-Length', '12')]


class TestCustomIterable(WSGIBodyTest):
    def application(self, env, start_response):
        start_response('200 ok', [])
        class foo(object):
            def __iter__(self):
                for char in 'thisisacustomstringfromacustomiterable':
                    yield char
        return foo()

    body = 'thisisacustomstringfromacustomiterable'


