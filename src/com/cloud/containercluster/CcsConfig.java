/*
 * Copyright 2016 ShapeBlue Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloud.containercluster;

import com.cloud.server.ManagementServer;

public enum CcsConfig {



    ContainerClusterTemplateName("Advanced", ManagementServer.class, String.class, "cloud.container.cluster.template.name", null, "name of the template used for creating containe cluster", null, null),
    ContainerClusterMasterCloudConfig("Advanced", ManagementServer.class, String.class, "cloud.container.cluster.master.cloudconfig", null, "file location path of the cloud config used for creating       container cluster master node", null, null),
    ContainerClusterNodeCloudConfig("Advanced", ManagementServer.class, String.class, "cloud.container.cluster.node.cloudconfig", null, "file location path of the cloud config used for creating           container cluster node", null, null),
    ContainerClusterNetworkOffering("Advanced", ManagementServer.class, String.class, "cloud.container.cluster.network.offering", null, "Name of the network offering that will be used to create           isolated network in which container cluster VMs will be launched.", null, null);


    private final String _category;
    private final Class<?> _componentClass;
    private final Class<?> _type;
    private final String _name;
    private final String _defaultValue;
    private final String _description;
    private final String _range;
    private final String _scope;

    private CcsConfig(String category, Class<?> componentClass, Class<?> type, String name, String defaultValue, String description, String range, String scope) {
        _category = category;
        _componentClass = componentClass;
        _type = type;
        _name = name;
        _defaultValue = defaultValue;
        _description = description;
        _range = range;
        _scope = scope;
    }

    public String getCategory() {
        return _category;
    }

    public String key() {
        return _name;
    }

    public String getDescription() {
        return _description;
    }

    public String getDefaultValue() {
        return _defaultValue;
    }

    public Class<?> getType() {
        return _type;
    }

    public Class<?> getComponentClass() {
        return _componentClass;
    }

    public String getScope() {
        return _scope;
    }

}
