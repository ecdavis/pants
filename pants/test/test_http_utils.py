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

import os
import unittest

from pants.http.utils import *

###############################################################################
# Test HTTP Utilities
###############################################################################

class HTTPHeadersTest(unittest.TestCase):
    def test_headers(self):
        data = HTTPHeaders()
        data['Content-Type'] = 'text/plain'
        
        self.assertEqual(data['content-type'], data['Content-Type'])
        self.assertTrue('CONTENT-TYPE' in data)
        
        del data['CoNtEnT-tYpE']

        self.assertFalse('Content-Type' in data)
        self.assertTrue(data.get('Content-Type') is None)

class FunctionTests(unittest.TestCase):
    def test_get_filename(self):
        with open(__file__) as f:
            self.assertEqual(os.path.basename(get_filename(f)),
                os.path.basename(__file__))

    def test_generate_signature(self):
        self.assertEqual(
            generate_signature("whee", "one", "two", "three"),
            "7d767d29a065e3445184b6d8369bcea03a50fdd8"
        )

    def test_content_type(self):
        self.assertEqual(content_type("test.txt"), "text/plain")

    def test_read_headers(self):
        # read_headers is fussy now about line breaks.
        headers = read_headers(CRLF.join("""Content-Type: text/plain; charset=UTF-8
Content-Length: 12
Content-Encoding: gzip
Server: HTTPants/some-ver
Other-Header: Blah
Set-Cookie: fish=true;
Set-Cookie: pie=blah""".splitlines()))

        self.assertEqual(headers["content-length"], headers["Content-Length"])
        self.assertEqual(int(headers["content-length"]), 12)
        self.assertEqual(len(headers["set-cookie"]), 2)

    def test_bad_headers(self):
        with self.assertRaises(BadRequest):
            read_headers(CRLF.join("""Test: fish

Cake: free""".splitlines()))
