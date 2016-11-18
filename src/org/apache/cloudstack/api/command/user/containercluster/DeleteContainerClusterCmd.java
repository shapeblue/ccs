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
package org.apache.cloudstack.api.command.user.containercluster;

import com.cloud.containercluster.CcsEventTypes;
import com.cloud.containercluster.ContainerCluster;
import com.cloud.containercluster.ContainerClusterService;
import com.cloud.exception.ConcurrentOperationException;
import com.cloud.exception.InsufficientCapacityException;
import com.cloud.exception.NetworkRuleConflictException;
import com.cloud.exception.ResourceAllocationException;
import com.cloud.exception.ResourceUnavailableException;
import org.apache.cloudstack.acl.RoleType;
import org.apache.cloudstack.api.APICommand;
import org.apache.cloudstack.api.ApiConstants;
import org.apache.cloudstack.api.ApiErrorCode;
import org.apache.cloudstack.api.BaseAsyncCmd;
import org.apache.cloudstack.api.Parameter;
import org.apache.cloudstack.api.ServerApiException;
import org.apache.cloudstack.api.response.ContainerClusterResponse;
import org.apache.cloudstack.api.response.SuccessResponse;
import org.apache.cloudstack.context.CallContext;
import org.apache.log4j.Logger;

import javax.inject.Inject;

@APICommand(name = "deleteContainerCluster",
        description = "deletes a container cluster",
        responseObject = SuccessResponse.class,
        entityType = {ContainerCluster.class},
        authorized = {RoleType.Admin, RoleType.ResourceAdmin, RoleType.DomainAdmin, RoleType.User})
public class DeleteContainerClusterCmd extends BaseAsyncCmd {

    public static final Logger s_logger = Logger.getLogger(DeleteContainerClusterCmd.class.getName());

    private static final String s_name = "deletecontaierclusterresponse";

    /////////////////////////////////////////////////////
    //////////////// API parameters /////////////////////
    /////////////////////////////////////////////////////

    @Parameter(name = ApiConstants.ID,
            type = CommandType.UUID,
            entityType = ContainerClusterResponse.class,
            required = true,
            description = "the ID of the container cluster")
    private Long id;

    /////////////////////////////////////////////////////
    /////////////////// Accessors ///////////////////////
    /////////////////////////////////////////////////////

    public Long getId() {
        return id;
    }

    @Inject
    public ContainerClusterService _containerClusterService;

    /////////////////////////////////////////////////////
    /////////////// API Implementation///////////////////
    /////////////////////////////////////////////////////


    @Override
    public void execute() throws ResourceUnavailableException, InsufficientCapacityException,
            ServerApiException, ConcurrentOperationException, ResourceAllocationException,
            NetworkRuleConflictException {
        try {
            _containerClusterService.deleteContainerCluster(id);
            SuccessResponse response = new SuccessResponse(getCommandName());
            setResponseObject(response);
        } catch (Exception e) {
            s_logger.warn("Failed to delete vm container cluster due to " + e);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to delete vm container cluster", e);
        }
    }

    @Override
    public String getCommandName() {
        return s_name;
    }

    @Override
    public long getEntityOwnerId() {
        return CallContext.current().getCallingAccount().getId();
    }


    @Override
    public String getEventType() {
        return CcsEventTypes.EVENT_CONTAINER_CLUSTER_DELETE;
    }

    @Override
    public String getEventDescription() {
        return "Deleting container cluster. Cluster Id: " + getId();
    }

}
