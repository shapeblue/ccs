// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
(function($, cloudStack) {
    var vmMigrationHostObjs, ostypeObjs;

    cloudStack.sections.containerclusters = {
        title: 'label.containerclusters',
        id: 'containerclusters',
        sections: {
            containercluster: {
                id: 'containerclusters',
                listView: {
                    section: 'containercluster',
                    filters: {
                        all: {
                            label: 'ui.listView.filters.all'
                        },
                        running: {
                            label: 'state.Running'
                        },
                        destroyed: {
                            preFilter: function(args) {
                                if (isAdmin() || isDomainAdmin())
                                    return true;
                                else
                                    return false;
                            },
                            label: 'state.Destroyed'
                        }
                    },
                     fields: {
                         name: {
                             label: 'label.name'
                         },
                         zonename: {
                             label: 'label.zone.name'
                         },
                         clustersize : {
                             label: 'label.clustersize'
                         },
                         cpunumber: {
                             label: 'label.num.cpu.cores'
                         },
                         memory: {
                             label: 'label.memory.mb'
                         },
                         state: {
                             label: 'label.state',
                             indicator: {
                                 'Running': 'on',
                                 'Stopped': 'off',
                                 'Destroyed': 'off',
                                 'Error': 'off'
                             }
                         }
                     },

                    advSearchFields: {
                        name: {
                            label: 'label.name'
                        },
                        zoneid: {
                            label: 'label.zone',
                            select: function(args) {
                                $.ajax({
                                    url: createURL('listZones'),
                                    data: {
                                        listAll: true
                                    },
                                    success: function(json) {
                                        var zones = json.listzonesresponse.zone ? json.listzonesresponse.zone : [];

                                        args.response.success({
                                            data: $.map(zones, function(zone) {
                                                return {
                                                    id: zone.id,
                                                    description: zone.name
                                                };
                                            })
                                        });
                                    }
                                });
                            }
                        },
                    },

                    // List view actions
                    actions: {
                        add: {
                            label: 'label.containercluster.add',

                            createForm: {
                                title: 'label.containercluster.add',
                                preFilter: cloudStack.preFilter.createTemplate,
                                fields: {
                                    name: {
                                        label: 'label.name',
                                        docID: 'helpContainerClusterName',
                                        validation: {
                                            required: true
                                        }
                                    },
                                    description: {
                                        label: 'label.description',
                                        docID: 'helpContainerClusterDesc',
                                    },
                                    zone: {
                                        label: 'label.zone',
                                        docID: 'helpContainerClusterZone',
                                        validation: {
                                            required: true
                                        },
                                        select: function(args) {
                                                $.ajax({
                                                    url: createURL("listZones&available=true"),
                                                    dataType: "json",
                                                    async: true,
                                                    success: function(json) {
                                                        var zoneObjs = [];
                                                        var items = json.listzonesresponse.zone;
                                                        if (items != null) {
                                                            for (var i = 0; i < items.length; i++) {
                                                                zoneObjs.push({
                                                                    id: items[i].id,
                                                                    description: items[i].name
                                                                });
                                                            }
                                                        }
                                                        args.response.success({
                                                            data: zoneObjs
                                                        });
                                                    }
                                                });
                                        }
                                    },
                                    serviceoffering: {
                                        label: 'label.menu.service.offerings',
                                        docID: 'helpContainerClusterServiceOffering',
                                        validation: {
                                            required: true
                                        },
                                        select: function(args) {
                                                $.ajax({
                                                    url: createURL("listServiceOfferings"),
                                                    dataType: "json",
                                                    async: true,
                                                    success: function(json) {
                                                        var offeringObjs = [];
                                                        var items = json.listserviceofferingsresponse.serviceoffering;
                                                        if (items != null) {
                                                            for (var i = 0; i < items.length; i++) {
                                                                offeringObjs.push({
                                                                    id: items[i].id,
                                                                    description: items[i].name
                                                                });
                                                            }
                                                        }
                                                        args.response.success({
                                                            data: offeringObjs
                                                        });
                                                    }
                                                });
                                        }
                                    },
                                    network: {
                                        label: 'label.network',
                                        docID: 'helpContainerClusterNetwork',
                                        select: function(args) {
                                                $.ajax({
                                                    url: createURL("listNetworks"),
                                                    dataType: "json",
                                                    async: true,
                                                    success: function(json) {
                                                        var networkObjs = [];
                                                        networkObjs.push({
                                                            id: "",
                                                            description: ""
                                                        });
                                                        var items = json.listnetworksresponse.network;
                                                        if (items != null) {
                                                            for (var i = 0; i < items.length; i++) {
                                                                networkObjs.push({
                                                                    id: items[i].id,
                                                                    description: items[i].name
                                                                });
                                                            }
                                                        }
                                                        args.response.success({
                                                            data: networkObjs
                                                        });
                                                    }
                                                });
                                        }
                                    },
                                    clustersize: {
                                        label: 'label.clustersize',
                                        docID: 'helpContainerClusterSize',
                                        validation: {
                                            required: true
                                        },
                                    },
                                    sshkeypair: {
                                        label: 'label.menu.sshkeypair',
                                        docID: 'helpContainerClusterSSH',
                                        select: function(args) {
                                                $.ajax({
                                                    url: createURL("listSSHKeyPairs"),
                                                    dataType: "json",
                                                    async: true,
                                                    success: function(json) {
                                                        var keypairObjs = [];
                                                        keypairObjs.push({
                                                            id: "",
                                                            description: ""
                                                        });
                                                        var items = json.listsshkeypairsresponse.sshkeypair;
                                                        if (items != null) {
                                                            for (var i = 0; i < items.length; i++) {
                                                                keypairObjs.push({
                                                                        id: items[i].name,
                                                                        description: items[i].name
                                                                });
                                                            }
                                                        }
                                                        args.response.success({
                                                            data: keypairObjs
                                                        });
                                                    }
                                                });
                                        }
                                    }
                                }
                            },

                            action: function(args) {
                                var data = {
                                    name: args.data.name,
                                    description: args.data.description,
                                    zoneid: args.data.zone,
                                    serviceofferingid: args.data.serviceoffering,
                                    clustersize: args.data.clustersize,
                                    keypair: args.data.sshkeypair
                                };
                                if (args.data.network != null && args.data.network.length > 0) {
                                        $.extend(data, {
                                            networkid: args.data.network
                                        });
                                }
                                $.ajax({
                                    url: createURL('createContainerCluster'),
                                    data: data,
                                    success: function(json) {
                                        args.response.success({data: json.createcontainerclusterresponse});
                                    },
                                    error: function(XMLHttpResponse) {
                                        var errorMsg = parseXMLHttpResponse(XMLHttpResponse);
                                        args.response.error(errorMsg);
                                    }
                                });
                            },


                            messages: {
                                notification: function(args) {
                                    return 'label.containercluster.add';
                                }
                            },
                            notification: {
                                poll: pollAsyncJobResult
                            }
                        }
                    },

                    dataProvider: function(args) {
                        var data = {};
                        listViewDataProvider(args, data);

                        if (args.filterBy != null) { //filter dropdown
                            if (args.filterBy.kind != null) {
                                switch (args.filterBy.kind) {
                                    case "all":
                                        break;
                                    case "running":
                                        $.extend(data, {
                                            state: 'Running'
                                        });
                                        break;
                                    case "destroyed":
                                        $.extend(data, {
                                            state: 'Destroyed'
                                        });
                                        break;
                                }
                            }
                        }

                        $.ajax({
                            url: createURL("listContainerCluster"),
                            data: data,
                            success: function(json) {
                                var items = json.listcontainerclusterresponse.containercluster;
                                args.response.success({
                                    data: items
                                });
                            }
                        });
                    },

                    detailView: {
                        name: 'container cluster details',
                        isMaximized: true,
                        viewAll: [{
                            label: 'label.cluster.vms',
                            path: 'containerclusters.clusterinstances'
                        }],
                        actions: {
                            destroy: {
                                label: 'label.action.containercluster.instance',
                                compactLabel: 'label.destroy',
                                createForm: {
                                    title: 'label.action.containercluster.instance',
                                    desc: 'label.action.containercluster.instance',
                                    isWarning: true,
                                    fields: {
                                    }
                                },
                                messages: {
                                    notification: function(args) {
                                        return 'label.action.destroy.instance';
                                    }
                                },
                                action: function(args) {
                                    var data = {
                                        id: args.context.containerclusters[0].id
                                    };
                                    $.ajax({
                                        url: createURL('deleteContainerCluster'),
                                        data: data,
                                        dataType: "json",
                                        async: true,
                                        success: function(json) {
                                            args.response.success({
                                                _custom: {
                                                    jobId: json.deletecontaierclusterresponse.jobid
                                                }
                                            });
                                        }
                                    });
                                },
                                notification: {
                                    poll: pollAsyncJobResult
                                }
                            }
                        },
                        tabs: {
                            // Details tab
                            details: {
                                title: 'label.details',
                                fields: [{
                                     id: {
                                         label: 'label.id'
                                     },
                                     name: {
                                         label: 'label.name'
                                     },
                                     zonename: {
                                         label: 'label.zone.name'
                                     },
                                     clustersize : {
                                         label: 'label.clustersize'
                                     },
                                     cpunumber: {
                                         label: 'label.num.cpu.cores'
                                     },
                                     memory: {
                                         label: 'label.memory.mb'
                                     },
                                     state: {
                                         label: 'label.state',
                                     },
                                     serviceofferingname: {
                                         label: 'label.compute.offering'
                                     },
                                     associatednetworkname: {
                                         label: 'label.network'
                                     },
                                     keypair: {
                                         label: 'label.menu.sshkeypair'
                                     },
                                     endpoint: {
                                         label: 'API endpoint',
                                         isCopyPaste: true
                                     },
                                     consoleendpoint: {
                                         label: 'Dashboard endpoint',
                                         isCopyPaste: true
                                     },
                                     userid: {
                                         label: 'username',
                                         isCopyPaste: true
                                     },
                                     password: {
                                         label: 'password',
                                         isCopyPaste: true
                                     }
                                }],

                                dataProvider: function(args) {
                                    $.ajax({
                                        url: createURL("listContainerCluster&id=" + args.context.containerclusters[0].id),
                                        dataType: "json",
                                        async: true,
                                        success: function(json) {
                                            var jsonObj;
                                            if (json.listcontainerclusterresponse.containercluster != null && json.listcontainerclusterresponse.containercluster.length > 0)
                                                jsonObj = json.listcontainerclusterresponse.containercluster[0];
                                            args.response.success({
                                                data: jsonObj
                                            });
                                        }
                                    });
                                }
                            },
                            console : {
                               title: 'Dashboard',
                                custom : function (args) {
                                    var s1 = '<iframe src="';
                                    var s2 = args.context.containerclusters[0].consoleendpoint;
                                    var s3 = '" width="940" height="600")>';
                                    return jQuery(s1.concat(s2, s3));
                                }
                            }
                        }
                    }
                }
            },
            clusterinstances: {
                id: 'clusterinstances',
                listView: {
                    section: 'clusterinstances',
                    fields: {
                        name: {
                            label: 'label.name',
                            truncate: true
                        },
                        instancename: {
                            label: 'label.internal.name'
                        },
                        displayname: {
                            label: 'label.display.name',
                            truncate: true
                        },
                        ipaddress: {
                            label: 'label.ip.address'
                        },
                        zonename: {
                            label: 'label.zone.name'
                        },
                        state: {
                            label: 'label.state',
                            indicator: {
                                'Running': 'on',
                                'Stopped': 'off',
                                'Destroyed': 'off',
                                'Error': 'off'
                            }
                        }
                    },
                    dataProvider: function(args) {
                                    var data = {};
                                    listViewDataProvider(args, data);

                                    if (args.filterBy != null) { //filter dropdown
                                        if (args.filterBy.kind != null) {
                                            switch (args.filterBy.kind) {
                                                case "all":
                                                    break;
                                                case "mine":
                                                    if (!args.context.projects) {
                                                        $.extend(data, {
                                                            domainid: g_domainid,
                                                            account: g_account
                                                        });
                                                    }
                                                    break;
                                                case "running":
                                                    $.extend(data, {
                                                        state: 'Running'
                                                    });
                                                    break;
                                                case "stopped":
                                                    $.extend(data, {
                                                        state: 'Stopped'
                                                    });
                                                    break;
                                                case "destroyed":
                                                    $.extend(data, {
                                                        state: 'Destroyed'
                                                    });
                                                    break;
                                            }
                                        }
                                    }

                                    if ("virtualmachineids" in args.context.containerclusters[0]) {
                                        var vlist = args.context.containerclusters[0].virtualmachineids.join();
                                        $.extend(data, {
                                            ids: vlist
                                        });
                                    }

                                    $.ajax({
                                        url: createURL('listVirtualMachines'),
                                        data: data,
                                        success: function(json) {
                                            var items = json.listvirtualmachinesresponse.virtualmachine;
                                            if (items) {
                                                $.each(items, function(idx, vm) {
                                                    if (vm.nic && vm.nic.length > 0 && vm.nic[0].ipaddress) {
                                                        items[idx].ipaddress = vm.nic[0].ipaddress;
                                                    }
                                                });
                                            }
                                            args.response.success({
                                                data: items
                                            });
                                        },
                                        error: function(XMLHttpResponse) {
                                            cloudStack.dialog.notice({
                                                message: parseXMLHttpResponse(XMLHttpResponse)
                                            });
                                            args.response.error();
                                         }
                                    });
                                },
                }
            }
        }
    };

})(jQuery, cloudStack);
