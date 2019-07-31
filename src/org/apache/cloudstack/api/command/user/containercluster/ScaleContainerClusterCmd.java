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

package org.apache.cloudstack.api.command.user.containercluster;

import javax.inject.Inject;

import org.apache.cloudstack.acl.RoleType;
import org.apache.cloudstack.acl.SecurityChecker;
import org.apache.cloudstack.api.ACL;
import org.apache.cloudstack.api.APICommand;
import org.apache.cloudstack.api.ApiConstants;
import org.apache.cloudstack.api.ApiErrorCode;
import org.apache.cloudstack.api.BaseAsyncCmd;
import org.apache.cloudstack.api.Parameter;
import org.apache.cloudstack.api.ResponseObject;
import org.apache.cloudstack.api.ServerApiException;
import org.apache.cloudstack.api.response.ContainerClusterResponse;
import org.apache.cloudstack.api.response.ServiceOfferingResponse;
import org.apache.cloudstack.context.CallContext;
import org.apache.log4j.Logger;

import com.cloud.containercluster.CcsEventTypes;
import com.cloud.containercluster.ContainerCluster;
import com.cloud.containercluster.ContainerClusterService;
import com.cloud.exception.ConcurrentOperationException;
import com.cloud.exception.InsufficientCapacityException;
import com.cloud.exception.ManagementServerException;
import com.cloud.exception.NetworkRuleConflictException;
import com.cloud.exception.ResourceAllocationException;
import com.cloud.exception.ResourceUnavailableException;

@APICommand(name = ScaleContainerClusterCmd.APINAME, description = "Scales a created or running container cluster",
        responseObject = ContainerClusterResponse.class,
        responseView = ResponseObject.ResponseView.Restricted,
        entityType = {ContainerCluster.class},
        requestHasSensitiveInfo = false,
        responseHasSensitiveInfo = true,
        authorized = {RoleType.Admin, RoleType.ResourceAdmin, RoleType.DomainAdmin, RoleType.User})
public class ScaleContainerClusterCmd extends BaseAsyncCmd {

    public static final Logger s_logger = Logger.getLogger(StartContainerClusterCmd.class.getName());

    public static final String APINAME = "scaleContainerCluster";

    @Inject
    public ContainerClusterService containerClusterService;

    /////////////////////////////////////////////////////
    //////////////// API parameters /////////////////////
    /////////////////////////////////////////////////////
    @Parameter(name = ApiConstants.ID, type = CommandType.UUID,
            entityType = ContainerClusterResponse.class,
            description = "the ID of the container cluster")
    private Long id;

    @ACL(accessType = SecurityChecker.AccessType.UseEntry)
    @Parameter(name = ApiConstants.SERVICE_OFFERING_ID, type = CommandType.UUID, entityType = ServiceOfferingResponse.class,
            description = "the ID of the service offering for the virtual machines in the cluster.")
    private Long serviceOfferingId;

    @Parameter(name=ApiConstants.SIZE, type = CommandType.LONG,
            description = "number of container cluster nodes")
    private Long clusterSize;

    /////////////////////////////////////////////////////
    /////////////////// Accessors ///////////////////////
    /////////////////////////////////////////////////////

    public Long getId() {
        return id;
    }

    public Long getServiceOfferingId() {
        return serviceOfferingId;
    }

    public Long getClusterSize() {
        return clusterSize;
    }

    @Override
    public String getEventType() {
        return CcsEventTypes.EVENT_CONTAINER_CLUSTER_SCALE;
    }

    @Override
    public String getEventDescription() {
        return "Scaling container cluster id: " + getId();
    }

    @Override
    public String getCommandName() {
        return APINAME.toLowerCase() + "response";
    }

    @Override
    public long getEntityOwnerId() {
        return CallContext.current().getCallingAccount().getId();
    }

    /////////////////////////////////////////////////////
    /////////////// API Implementation///////////////////
    /////////////////////////////////////////////////////
    public ContainerCluster validateRequest() {
        if (getId() == null || getId() < 1L) {
            throw new ServerApiException(ApiErrorCode.PARAM_ERROR, "Invalid container cluster ID provided");
        }
        final ContainerCluster containerCluster = containerClusterService.findById(getId());
        if (containerCluster == null) {
            throw new ServerApiException(ApiErrorCode.PARAM_ERROR, "Given container cluster was not found");
        }
        return containerCluster;
    }

    @Override
    public void execute() throws ResourceUnavailableException, InsufficientCapacityException, ServerApiException, ConcurrentOperationException, ResourceAllocationException, NetworkRuleConflictException {
        final ContainerCluster containerCluster = validateRequest();
        try {
            containerClusterService.scaleContainerCluster(this);
            final ContainerClusterResponse response = containerClusterService.createContainerClusterResponse(getId());
            response.setResponseName(getCommandName());
            setResponseObject(response);
        } catch (InsufficientCapacityException | ResourceUnavailableException | ManagementServerException ex) {
            s_logger.warn("Failed to scale container cluster:" + containerCluster.getUuid() + " due to " + ex.getMessage());
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR,
                    "Failed to scale container cluster:" + containerCluster.getUuid(), ex);
        }
    }
}
