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

###############################################################################
# Imports
###############################################################################

from pants.http.utils import *

###############################################################################
# BaseAuth Class
###############################################################################

class AuthBase(object):
    def __call__(self, request):
        raise NotImplementedError("BaseAuth instances must be callable.")

def _basic_auth(username, password):
    return 'Basic ' + base64.b64encode('%s:%s' % (username, password))

###############################################################################
# Basic Authentication
###############################################################################

class BasicAuth(AuthBase):
    """ Basic HTTP authentication. """
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __call__(self, request):
        request.headers['Authorization'] = _basic_auth(self.username,
                                                       self.password)
        return request

class ProxyAuth(BasicAuth):
    """ Basic Proxy-Authorization """
    def __call__(self, request):
        request.headers['Proxy-Authorization'] = _basic_auth(self.username,
                                                             self.password)
        return request

###############################################################################
# Digest Authentication
###############################################################################

# TODO: Write Digest Authentication
