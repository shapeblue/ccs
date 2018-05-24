# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

""" Base class for all CCS resources
"""

import marvin
from marvin.cloudstackAPI import *
from marvin.ccsAPI import *
from marvin.lib.utils import validateList, is_server_ssh_ready, random_gen, wait_until
# Import System modules
import time
import haslib
import base64

class ContainerCluster:
    """ Container Cluster Life Cycle """

    STOPPED = STOPPED
    RUNNING = RUNNING

    def __init__(self, items):
        self.__dict__.update(items)

    @classmethod
    def create(cls, apiclient, name, zoneid, serviceofferingid, size):
        """ Creates a Container Cluster """
        cmd = createContainerCluster.createContainerClusterCmd
        cmd.name = name
        cmd.zoneid = zoneid
        cmd. serviceofferingid = serviceofferingid
        cmd.size = size
        cluster = apiclient.createContainerCluster(cmd)
        return ContainerCluster(cluster.__dict__)

    def stop(self, apiclient, cmd):
        """ Stops a Container Cluster """
        apiclient.stopContainerCluster(cmd)
        return self.getState(apiclient, ContainerCluster.STOPPED)

    def start(self, apiclient, cmd):
        """ Start a Container Cluster """
        apiclient.startContainerCluster(cmd)
        return self.getState(apiclient, ContainerCluster.RUNNING)

    def list(self, apiclient, cmd):
        """ Lust Container Clusters """
        return apiclient.listContainerCluster(cmd)

    def getState(self, apiclient, state, timeout=600):
        """List Conatiner Cluster and check if its state is as expected
        @returnValue - List[Result, Reason]
                       1) Result - FAIL if there is any exception
                       in the operation or VM state does not change
                       to expected state in given time else PASS
                       2) Reason - Reason for failure"""

        returnValue = [FAIL, "Container Cluster state not trasited to %s,\
                        operation timed out" % state]

        while timeout > 0:
            try:
                cmd = listContainerCluster.listContainerClusterCmd()
                clusters = ContainerCluster.list(apiclient, cmd)
                validationresult = validateList(clusters)
                if validationresult[0] == FAIL:
                    raise Exception("Container Cluster list validation failed: %s" % validationresult[2])
                elif str(clusters[0].state).lower().decode("string_escape") == str(state).lower():
                    returnValue = [PASS, None]
                    break
            except Exception as e:
                returnValue = [FAIL, e]
                break
            time.sleep(60)
            timeout -= 60
        return returnValue