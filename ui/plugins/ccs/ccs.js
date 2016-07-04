(function (cloudStack) {

    var rootCaCert = "";
    cloudStack.plugins.ccs = function(plugin) {
        plugin.ui.addSection({
            id: 'ccs',
            title: 'Container Service',
            preFilter: function(args) {
                return true;
            },
            showOnNavigation: true,
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
                            size : {
                                label: 'label.size'
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
                            showCACert: {
                                label: 'Cluster Root CA Certificate',
                                isHeader: true,
                                messages: {
                                    notification: function(args) {
                                        return 'Cluster Root CA Certificate';
                                    }
                                },
                                createForm: {
                                    title: 'Cluster Root CA Certificate',
                                    fields: {
                                        certificate: {
                                            label: 'label.certificate',
                                            isTextarea: true,
                                            defaultValue: function(args) {
                                                $.ajax({
                                                    url: createURL("listContainerClusterCACert"),
                                                    dataType: "json",
                                                    async: false,
                                                    success: function(json) {
                                                        rootCaCert = json.listcontainerclustercacertresponse.rootcacert.certificate;
                                                    }
                                                });
                                                return rootCaCert;
                                            }
                                        }
                                    }
                                },
                                action: function(args) {
                                    var blob = new Blob([rootCaCert], {type: 'application/x-x509-ca-cert'});
                                    var filename = "cloudstack-containerservice.pem";
                                    if(window.navigator.msSaveOrOpenBlob) {
                                        window.navigator.msSaveBlob(blob, filename);
                                    } else{
                                        var elem = window.document.createElement('a');
                                        elem.href = window.URL.createObjectURL(blob);
                                        elem.download = filename;
                                        document.body.appendChild(elem)
                                        elem.click();
                                        document.body.removeChild(elem);
                                    }
                                    args.response.success({});
                                },
                            },
                            add: {
                                label: 'Add container cluster',
                                createForm: {
                                    title: 'Add container cluster',
                                    preFilter: cloudStack.preFilter.createTemplate,
                                    fields: {
                                        name: {
                                            label: 'label.name',
                                            //docID: 'Name of the cluster',
                                            validation: {
                                                required: true
                                            }
                                        },
                                        description: {
                                            label: 'label.description',
                                            //docID: 'helpContainerClusterDesc',
                                        },
                                        zone: {
                                            label: 'label.zone',
                                            //docID: 'helpContainerClusterZone',
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
                                            //docID: 'helpContainerClusterServiceOffering',
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
                                            //docID: 'helpContainerClusterNetwork',
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
                                        size: {
                                            label: 'Cluster size',
                                            //docID: 'helpContainerClusterSize',
                                            validation: {
                                                required: true
                                            },
                                        },
                                        sshkeypair: {
                                            label: 'SSH keypair',
                                            //docID: 'helpContainerClusterSSH',
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
                                        },
                                        supportPrivateRegistry: {
                                            label: 'Private Registry',
                                            isBoolean: true,
                                            isChecked: false,
                                        },
                                        username: {
                                            label: 'label.username',
                                            dependsOn: 'supportPrivateRegistry',
                                            validation: {
                                                required: true
                                            },
                                            isHidden: true
                                        },
                                        password: {
                                            label: 'label.password',
                                            dependsOn: 'supportPrivateRegistry',
                                            validation: {
                                                required: true
                                            },
                                            isHidden: true,
                                            isPassword: true
                                        },
                                        url: {
                                            label: 'label.url',
                                            dependsOn: 'supportPrivateRegistry',
                                            validation: {
                                                required: true
                                            },
                                            isHidden: true,
                                        },
                                        email: {
                                            label: 'label.email',
                                            dependsOn: 'supportPrivateRegistry',
                                            validation: {
                                                required: true
                                            },
                                            isHidden: true,
                                        }
                                    }
                                },

                                action: function(args) {
                                    var data = {
                                        name: args.data.name,
                                        description: args.data.description,
                                        zoneid: args.data.zone,
                                        serviceofferingid: args.data.serviceoffering,
                                        size: args.data.size,
                                        keypair: args.data.sshkeypair
                                    };

                                    if (args.data.supportPrivateRegistry) {
                                        $.extend(data, {
                                            dockerregistryusername: args.data.username,
                                            dockerregistrypassword: args.data.password,
                                            dockerregistryurl: args.data.url,
                                            dockerregistryemail: args.data.email
                                        });
                                    }

                                    if (args.data.network != null && args.data.network.length > 0) {
                                        $.extend(data, {
                                            networkid: args.data.network
                                        });
                                    }
                                    $.ajax({
                                        url: createURL('createContainerCluster'),
                                        data: data,
                                        success: function(json) {
                                            var jid = json.createcontainerclusterresponse.jobid;
                                            args.response.success({
                                                _custom: {
                                                    jobId: jid
                                                }
                                            });
                                        },
                                        error: function(XMLHttpResponse) {
                                            var errorMsg = parseXMLHttpResponse(XMLHttpResponse);
                                            args.response.error(errorMsg);
                                        }
                                    });
                                },


                                messages: {
                                    notification: function(args) {
                                        return 'Container Cluster Add';
                                    }
                                },
                                notification: {
                                    poll: pollAsyncJobResult
                                }
                            }
                        },

                        dataProvider: function(args) {
                            var data = {
                                    page: args.page,
                                    pagesize: pageSize
                                };
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
                                dataType: "json",
                                sync: true,
                                success: function(json) {
                                    var items = json.listcontainerclusterresponse.containercluster;
                                    args.response.success({
                                        actionFilter: ccsActionfilter,
                                        data: items
                                    });
                                }
                            });
                        },

                        detailView: {
                            name: 'container cluster details',
                            isMaximized: true,
                            actions: {
                                start: {
                                    label: 'Start Container Cluster',
                                    action: function(args) {
                                        $.ajax({
                                            url: createURL("startContainerCluster"),
                                            data: {"id": args.context.containerclusters[0].id},
                                            dataType: "json",
                                            async: true,
                                            success: function(json) {
                                                var jid = json.startcontainerclusterresponse.jobid;
                                                args.response.success({
                                                    _custom: {
                                                        jobId: jid
                                                    }
                                                });
                                            }
                                        });
                                    },
                                    messages: {
                                        confirm: function(args) {
                                            return 'Please confirm that you want to start this container cluster.';
                                        },
                                        notification: function(args) {
                                            return 'Started container cluster.';
                                        }
                                    },
                                    notification: {
                                        poll: pollAsyncJobResult
                                    }
                                },
                                stop: {
                                    label: 'Stop Container Cluster',
                                    action: function(args) {
                                        $.ajax({
                                            url: createURL("stopContainerCluster"),
                                            data: {"id": args.context.containerclusters[0].id},
                                            dataType: "json",
                                            async: true,
                                            success: function(json) {
                                                var jid = json.stopcontainerclusterresponse.jobid;
                                                args.response.success({
                                                    _custom: {
                                                        jobId: jid
                                                    }
                                                });
                                            }
                                        });
                                    },
                                    messages: {
                                        confirm: function(args) {
                                            return 'Please confirm that you want to stop this container cluster.';
                                        },
                                        notification: function(args) {
                                            return 'Stopped container cluster.';
                                        }
                                    },
                                    notification: {
                                        poll: pollAsyncJobResult
                                    }
                                },
                                destroy: {
                                    label: 'Destroy Cluster',
                                    compactLabel: 'label.destroy',
                                    createForm: {
                                        title: 'Destroy Container Cluster',
                                        desc: 'Destroy Container Cluster',
                                        isWarning: true,
                                        fields: {
                                        }
                                    },
                                    messages: {
                                        confirm: function(args) {
                                            return 'Please confirm that you want to destroy this container cluster.';
                                        },
                                        notification: function(args) {
                                            return 'Destroyed container cluster.';
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
                                        size : {
                                            label: 'Cluster Size'
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
                                            label: 'Ssh Key Pair'
                                        },
                                        endpoint: {
                                            label: 'API endpoint',
                                            isCopyPaste: true
                                        },
                                        consoleendpoint: {
                                            label: 'Dashboard endpoint',
                                            isCopyPaste: true
                                        },
                                        username: {
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
                                                    actionFilter: ccsActionfilter,
                                                    data: jsonObj
                                                });
                                            }
                                        });
                                    }
                                },
                                console : {
                                    title: 'Dashboard',
                                    custom : function (args) {
                                        var endPoint = args.context.containerclusters[0].consoleendpoint;
                                        var username = args.context.containerclusters[0].username;
                                        var password = args.context.containerclusters[0].password;
                                        var protocol = endPoint.split("://")[0] + "://";
                                        var uri = endPoint.split("://")[1];

                                        var dashboardUrl = endPoint;
                                        if (username && password && endPoint) {
                                            dashboardUrl = protocol + username + ":" + password + "@" + uri;
                                        }
                                        var popOut = '<p align="right"><a href="' + dashboardUrl + '" target="_blank">Pop-out ↗</a></p>';
                                        var iframe = popOut + '<iframe src="';
                                        var iframeArgs = '" width="770" height="560")>';
                                        return jQuery(iframe.concat(dashboardUrl, iframeArgs));
                                    }
                                },
                                clusterinstances: {
                                    title: 'Instances',
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

                                            $.ajax({
                                                url: createURL("listContainerCluster"),
                                                data: {"id": args.context.containerclusters[0].id},
                                                success: function(json) {
                                                    var items = json.listcontainerclusterresponse.containercluster;

                                                    var vmlist = [];
                                                    $.each(items, function(idx, item) {
                                                        if ("virtualmachineids" in item) {
                                                            vmlist = vmlist.concat(item.virtualmachineids);
                                                        }
                                                    });

                                                    $.extend(data, {
                                                        ids: vmlist.join()
                                                    });

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
                                                }
                                            });
                                       },
                                    }
                                },
                                firewall: {
                                    title: 'label.firewall',
                                    custom: function(args) {
                                        $.ajax({
                                            url: createURL('listNetworks'),
                                            data: {id: args.context.containerclusters[0].networkid},
                                            async: false,
                                            dataType: "json",
                                            success: function(json) {
                                                var network = json.listnetworksresponse.network;
                                                $.extend(args.context, {"networks": [network]});
                                            }
                                        });

                                        $.ajax({
                                            url: createURL('listPublicIpAddresses'),
                                            data: {associatedNetworkId: args.context.containerclusters[0].networkid, forvirtualnetwork: true},
                                            async: false,
                                            dataType: "json",
                                            success: function(json) {
                                                var ips = json.listpublicipaddressesresponse.publicipaddress;
                                                var fwip = ips[0];
                                                $.each(ips, function(idx, ip) {
                                                    if (ip.issourcenat || ip.isstaticnat) {
                                                        fwip = ip;
                                                        return false;
                                                    }
                                                });
                                                $.extend(args.context, {"ipAddresses": [fwip]});
                                            }
                                        });
                                        return cloudStack.sections.network.sections.ipAddresses.listView.detailView.tabs.ipRules.custom(args);
                                    },
                                },
                            }
                        }
                    }
                },
            }

        });
    };

    var ccsActionfilter = cloudStack.actionFilter.ccsActionfilter = function(args) {
        var jsonObj = args.context.item;
        var allowedActions = [];
        if (jsonObj.state != "Destroyed" && jsonObj.state != "Destroying") {
            if (jsonObj.state == "Stopped") {
                allowedActions.push("start");
            } else {
                allowedActions.push("stop");
            }
            allowedActions.push("destroy");
        }
        return allowedActions;
    }

}(cloudStack));
