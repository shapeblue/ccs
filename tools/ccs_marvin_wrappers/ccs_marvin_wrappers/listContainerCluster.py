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


"""Lists container clusters"""
from baseCmd import *
from baseResponse import *
class listContainerClusterCmd (baseCmd):
    typeInfo = {}
    def __init__(self):
        self.isAsync = "false"
        """the ID of the container cluster"""
        self.id = None
        self.typeInfo['id'] = 'uuid'
        """List by keyword"""
        self.keyword = None
        self.typeInfo['keyword'] = 'string'
        """name of the container cluster (a substring match is made against the parameter value, data for all matching container clusters will be returned)"""
        self.name = None
        self.typeInfo['name'] = 'string'
        """"""
        self.page = None
        self.typeInfo['page'] = 'integer'
        """"""
        self.pagesize = None
        self.typeInfo['pagesize'] = 'integer'
        """state of the container cluster"""
        self.state = None
        self.typeInfo['state'] = 'string'
        self.required = []

class listContainerClusterResponse (baseResponse):
    typeInfo = {}
    def __init__(self):
        """the id of the container cluster"""
        self.id = None
        self.typeInfo['id'] = 'string'
        """the name of the Network associated with the IP address"""
        self.associatednetworkname = None
        self.typeInfo['associatednetworkname'] = 'string'
        """URL end point for the cluster UI"""
        self.consoleendpoint = None
        self.typeInfo['consoleendpoint'] = 'string'
        """cluster cpu cores"""
        self.cpunumber = None
        self.typeInfo['cpunumber'] = 'string'
        """Description of the container cluster"""
        self.description = None
        self.typeInfo['description'] = 'string'
        """URL end point for the cluster"""
        self.endpoint = None
        self.typeInfo['endpoint'] = 'string'
        """keypair details"""
        self.keypair = None
        self.typeInfo['keypair'] = 'string'
        """cluster size"""
        self.memory = None
        self.typeInfo['memory'] = 'string'
        """Name of the container cluster"""
        self.name = None
        self.typeInfo['name'] = 'string'
        """network id details"""
        self.networkid = None
        self.typeInfo['networkid'] = 'string'
        """Password with which container cluster is setup"""
        self.password = None
        self.typeInfo['password'] = 'string'
        """Service Offering id"""
        self.serviceofferingid = None
        self.typeInfo['serviceofferingid'] = 'string'
        """the name of the service offering of the virtual machine"""
        self.serviceofferingname = None
        self.typeInfo['serviceofferingname'] = 'string'
        """cluster size"""
        self.size = None
        self.typeInfo['size'] = 'string'
        """state of the cluster"""
        self.state = None
        self.typeInfo['state'] = 'string'
        """template id"""
        self.templateid = None
        self.typeInfo['templateid'] = 'string'
        """Username with which container cluster is setup"""
        self.username = None
        self.typeInfo['username'] = 'string'
        """the list of virtualmachine ids associated with this container cluster"""
        self.virtualmachineids = None
        self.typeInfo['virtualmachineids'] = 'list'
        """zone id"""
        self.zoneid = None
        self.typeInfo['zoneid'] = 'string'
        """zone name"""
        self.zonename = None
        self.typeInfo['zonename'] = 'string'

