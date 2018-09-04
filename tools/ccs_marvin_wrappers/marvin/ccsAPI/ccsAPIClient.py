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

"""Test Client for CCS API"""
import copy
from marvin.ccsAPI.createContainerCluster import createContainerClusterResponse
from marvin.ccsAPI.deleteContainerCluster import deleteContainerClusterResponse
from marvin.ccsAPI.listContainerClusterCACert import listContainerClusterCACertResponse
from marvin.ccsAPI.stopContainerCluster import stopContainerClusterResponse
from marvin.ccsAPI.startContainerCluster import startContainerClusterResponse
from marvin.ccsAPI.listContainerCluster import listContainerClusterResponse

class CCSAPIClient(object):
    def __init__(self, connection):
        self.connection = connection
        self._id = None

    def __copy__(self):
        return CCSAPIClient(copy.copy(self.connection))

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, identifier):
        self._id = identifier


    def createContainerCluster(self, command, method="GET"):
        response = createContainerClusterResponse()
        response = self.connection.marvinRequest(command, response_type=response, method=method)
        return response

    def deleteContainerCluster(self, command, method="GET"):
        response = deleteContainerClusterResponse()
        response = self.connection.marvinRequest(command, response_type=response, method=method)
        return response

    def listContainerClusterCACert(self, command, method="GET"):
        response = listContainerClusterCACertResponse()
        response = self.connection.marvinRequest(command, response_type=response, method=method)
        return response

    def stopContainerCluster(self, command, method="GET"):
        response = stopContainerClusterResponse()
        response = self.connection.marvinRequest(command, response_type=response, method=method)
        return response

    def startContainerCluster(self, command, method="GET"):
        response = startContainerClusterResponse()
        response = self.connection.marvinRequest(command, response_type=response, method=method)
        return response

    def listContainerCluster(self, command, method="GET"):
        response = listContainerClusterResponse()
        response = self.connection.marvinRequest(command, response_type=response, method=method)
        return response