###############################################################################
#
# Copyright 2011 Chris Davis
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

import logging


###############################################################################
# Logging Configuration
###############################################################################

if __debug__:
    LEVEL = logging.DEBUG
else:
    LEVEL = logging.DEBUG

logging.basicConfig(
    level=LEVEL,
    filename="pants.log",
    format="[%(asctime)-19s] %(name)-5s : %(levelname)-7s (%(module)s::%(funcName)s:%(lineno)d): %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S"
    )


###############################################################################
# Initialisation
###############################################################################

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(name)-5s : %(levelname)-7s %(message)s")
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
