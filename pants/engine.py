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

import time

from pants.publisher import publisher
from pants.reactor import reactor
from pants.scheduler import scheduler
import pants.shared
from pants.shared import log


###############################################################################
# Engine Class
###############################################################################

class Engine(object):
    """
    The singleton engine class.
    
    An instance of this class will initialise and continuously update
    the various parts of the Pants framework. The global instance of
    this class will suit almost all situations, and only one instance
    should be running at any given time.
    """
    def __init__(self):
        self.shutdown = False
    
    def poll(self):
        pants.shared.time = time.time()
        scheduler.poll()
    
    def start(self):
        """
        Start the engine.
        
        This method blocks until the engine is stopped. It should be
        called after your asynchronous application has been fully
        initialised and is ready to start.
        """
        if self.shutdown:
            self.shutdown = False
            return
        
        # Initialise engine.
        log.info("Starting engine.")
        publisher.publish("pants.engine.start")
        
        # Main loop.
        try:
            log.info("Entering main loop.")
            
            while not self.shutdown:
                self.poll()
                
                if self.shutdown:
                    break
                
                reactor.poll()
                publisher.publish("pants.engine.poll")
                
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception:
            log.exception("Uncaught exception in main loop.")
        
        # Graceful shutdown.
        log.info("Stopping engine.")
        publisher.publish("pants.engine.stop")
        
        log.info("Shutting down.")
        self.shutdown = False # If we decide to start up again.
    
    def stop(self):
        """
        Shut down the engine after the current main loop iteration.
        """
        self.shutdown = True


###############################################################################
# Initialisation
###############################################################################

#: The global engine object.
engine = Engine()
