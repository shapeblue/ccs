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

import com.cloud.containercluster.ContainerCluster;
import com.cloud.containercluster.ContainerClusterService;
import com.cloud.containercluster.CcsEventTypes;
import com.cloud.exception.InsufficientCapacityException;
import com.cloud.exception.ResourceAllocationException;
import com.cloud.exception.ManagementServerException;
import com.cloud.exception.ConcurrentOperationException;
import com.cloud.exception.ResourceUnavailableException;
import com.cloud.user.Account;
import org.apache.cloudstack.acl.RoleType;
import org.apache.cloudstack.acl.SecurityChecker.AccessType;
import org.apache.cloudstack.api.ACL;
import org.apache.cloudstack.api.APICommand;
import org.apache.cloudstack.api.ApiCommandJobType;
import org.apache.cloudstack.api.ApiConstants;
import org.apache.cloudstack.api.ApiErrorCode;
import org.apache.cloudstack.api.BaseAsyncCreateCmd;
import org.apache.cloudstack.api.Parameter;
import org.apache.cloudstack.api.ResponseObject.ResponseView;
import org.apache.cloudstack.api.ServerApiException;
import org.apache.cloudstack.api.response.DomainResponse;
import org.apache.cloudstack.api.response.NetworkResponse;
import org.apache.cloudstack.api.response.ProjectResponse;
import org.apache.cloudstack.api.response.ServiceOfferingResponse;
import org.apache.cloudstack.api.response.ContainerClusterResponse;
import org.apache.cloudstack.api.response.ZoneResponse;
import org.apache.cloudstack.context.CallContext;
import org.apache.log4j.Logger;

@APICommand(name = "createContainerCluster",
        description = "Creates a cluster of VM's for launching containers.",
        responseObject = ContainerClusterResponse.class,
        responseView = ResponseView.Restricted,
        entityType = {ContainerCluster.class},
        requestHasSensitiveInfo = false,
        responseHasSensitiveInfo = true,
        authorized = {RoleType.Admin, RoleType.DomainAdmin, RoleType.User}
)
public class CreateContainerClusterCmd extends BaseAsyncCreateCmd {

    public static final Logger s_logger = Logger.getLogger(CreateContainerClusterCmd.class.getName());

    private static final String s_name = "createcontainerclusterresponse";

    /////////////////////////////////////////////////////
    //////////////// API parameters /////////////////////
    /////////////////////////////////////////////////////

    @Parameter(name = ApiConstants.NAME, type = CommandType.STRING, required = true,  description = "name for the container cluster")
    private String name;

    @Parameter(name = ApiConstants.DESCRIPTION, type = CommandType.STRING, description = "description for the container cluster")
    private String description;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.ZONE_ID, type = CommandType.UUID, entityType = ZoneResponse.class, required = true,
            description = "availability zone in which container cluster to be launched")
    private Long zoneId;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.SERVICE_OFFERING_ID, type = CommandType.UUID, entityType = ServiceOfferingResponse.class,
            required = true, description = "the ID of the service offering for the virtual machines in the cluster.")
    private Long serviceOfferingId;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.ACCOUNT, type = CommandType.STRING, description = "an optional account for the" +
            " virtual machine. Must be used with domainId.")
    private String accountName;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.DOMAIN_ID, type = CommandType.UUID, entityType = DomainResponse.class,
            description = "an optional domainId for the virtual machine. If the account parameter is used, domainId must also be used.")
    private Long domainId;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.PROJECT_ID, type = CommandType.UUID, entityType = ProjectResponse.class,
            description = "Deploy cluster for the project")
    private Long projectId;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.NETWORK_ID, type = CommandType.UUID, entityType = NetworkResponse.class,
            description = "Network in which container cluster is to be launched")
    private Long networkId;

    @ACL(accessType = AccessType.UseEntry)
    @Parameter(name = ApiConstants.SSH_KEYPAIR, type = CommandType.STRING,
            description = "name of the ssh key pair used to login to the virtual machines")
    private String sshKeyPairName;

    @Parameter(name=ApiConstants.SIZE, type = CommandType.LONG,
            required = true, description = "number of container cluster nodes")
    private Long clusterSize;

    /////////////////////////////////////////////////////
    /////////////////// Accessors ///////////////////////
    /////////////////////////////////////////////////////

    public String getAccountName() {
        if (accountName == null) {
            return CallContext.current().getCallingAccount().getAccountName();
        }
        return accountName;
    }

    public String getDisplayName() {
        return description;
    }

    public Long getDomainId() {
        if (domainId == null) {
            return CallContext.current().getCallingAccount().getDomainId();
        }
        return domainId;
    }

    public Long getServiceOfferingId() {
        return serviceOfferingId;
    }

    public Long getZoneId() {
        return zoneId;
    }

    public Long getNetworkId() { return networkId;}

    public String getName() {
        return name;
    }

    public String getSSHKeyPairName() {
        return sshKeyPairName;
    }

    @Inject
    public ContainerClusterService _containerClusterService;

    /////////////////////////////////////////////////////
    /////////////// API Implementation///////////////////
    /////////////////////////////////////////////////////

    @Override
    public String getCommandName() {
        return s_name;
    }

    public static String getResultObjectName() {
        return "containercluster";
    }

    @Override
    public long getEntityOwnerId() {
        Long accountId = _accountService.finalyzeAccountId(accountName, domainId, projectId, true);
        if (accountId == null) {
            return CallContext.current().getCallingAccount().getId();
        }

        return accountId;
    }

    @Override
    public String getEventType() {
        return CcsEventTypes.EVENT_CONTAINER_CLUSTER_CREATE;
    }

    @Override
    public String getCreateEventType() {
        return CcsEventTypes.EVENT_CONTAINER_CLUSTER_CREATE;
    }

    @Override
    public String getCreateEventDescription() {
        return "creating container cluster";
    }

    @Override
    public String getEventDescription() {
        return "creating container cluster. Cluster Id: " + getEntityId();
    }

    @Override
    public ApiCommandJobType getInstanceType() {
        return ApiCommandJobType.VirtualMachine;
    }

    @Override
    public void execute() {

        ContainerCluster containerCluster;

        try {
            _containerClusterService.startContainerCluster(getEntityId());
            ContainerClusterResponse response = _containerClusterService.createContainerClusterResponse(getEntityId());
            response.setResponseName(getCommandName());
            setResponseObject(response);
        } catch (InsufficientCapacityException ex) {
            s_logger.warn("Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
            throw new ServerApiException(ApiErrorCode.INSUFFICIENT_CAPACITY_ERROR,
                    "Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
        } catch (ResourceUnavailableException ex) {
            s_logger.warn("Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
            throw new ServerApiException(ApiErrorCode.RESOURCE_UNAVAILABLE_ERROR,
                    "Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
        } catch (ResourceAllocationException ex) {
            s_logger.warn("Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
            throw new ServerApiException(ApiErrorCode.RESOURCE_ALLOCATION_ERROR,
                    "Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
        } catch (ManagementServerException ex) {
            s_logger.warn("Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR,
                    "Failed to deploy container cluster:" + getEntityUuid() + " due to " + ex.getMessage());
        }
    }

    @Override
    public void create() throws ResourceAllocationException {

        try {

            Account owner = _accountService.getActiveAccountById(getEntityOwnerId());

            ContainerCluster cluster = _containerClusterService.createContainerCluster(name,
                    description, zoneId, serviceOfferingId, owner, networkId, sshKeyPairName, clusterSize);

            if (cluster != null) {
                setEntityId(cluster.getId());
                setEntityUuid(cluster.getUuid());
            } else {
                throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to create container cluster");
            }
        }  catch (ConcurrentOperationException ex) {
            s_logger.error("Exception: ", ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, ex.getMessage());
        } catch (InsufficientCapacityException ex) {
            s_logger.error("Exception: ", ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, ex.getMessage());
        } catch (ManagementServerException me) {
            s_logger.error("Exception: ", me);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, me.getMessage());
        }
    }
}
