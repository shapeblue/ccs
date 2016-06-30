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

package com.cloud.containercluster;

import com.cloud.api.ApiDBUtils;
import com.cloud.capacity.CapacityManager;
import com.cloud.containercluster.dao.ContainerClusterDao;
import com.cloud.containercluster.dao.ContainerClusterDetailsDao;
import com.cloud.containercluster.dao.ContainerClusterVmMapDao;
import com.cloud.dc.ClusterDetailsDao;
import com.cloud.dc.ClusterDetailsVO;
import com.cloud.dc.ClusterVO;
import com.cloud.dc.DataCenter;
import com.cloud.dc.DataCenterVO;
import com.cloud.dc.dao.ClusterDao;
import com.cloud.dc.dao.DataCenterDao;
import com.cloud.deploy.DeployDestination;
import com.cloud.exception.ConcurrentOperationException;
import com.cloud.exception.InsufficientCapacityException;
import com.cloud.exception.InsufficientServerCapacityException;
import com.cloud.exception.InvalidParameterValueException;
import com.cloud.exception.ManagementServerException;
import com.cloud.exception.NetworkRuleConflictException;
import com.cloud.exception.PermissionDeniedException;
import com.cloud.exception.ResourceAllocationException;
import com.cloud.exception.ResourceUnavailableException;
import com.cloud.host.Host.Type;
import com.cloud.host.HostVO;
import com.cloud.network.Network;
import com.cloud.network.Network.Service;
import com.cloud.network.NetworkModel;
import com.cloud.network.NetworkService;
import com.cloud.network.PhysicalNetwork;
import com.cloud.network.dao.IPAddressDao;
import com.cloud.network.dao.IPAddressVO;
import com.cloud.network.dao.NetworkDao;
import com.cloud.network.dao.NetworkVO;
import com.cloud.network.dao.PhysicalNetworkDao;
import com.cloud.network.firewall.FirewallService;
import com.cloud.network.rules.FirewallRule;
import com.cloud.network.rules.PortForwardingRuleVO;
import com.cloud.network.rules.RulesService;
import com.cloud.network.rules.dao.PortForwardingRulesDao;
import com.cloud.offering.NetworkOffering;
import com.cloud.offerings.NetworkOfferingVO;
import com.cloud.offerings.dao.NetworkOfferingDao;
import com.cloud.offerings.dao.NetworkOfferingServiceMapDao;
import com.cloud.org.Grouping;
import com.cloud.resource.ResourceManager;
import com.cloud.service.ServiceOfferingVO;
import com.cloud.service.dao.ServiceOfferingDao;
import com.cloud.storage.VMTemplateVO;
import com.cloud.storage.VMTemplateZoneVO;
import com.cloud.storage.dao.VMTemplateDao;
import com.cloud.storage.dao.VMTemplateZoneDao;
import com.cloud.user.AccountManager;
import com.cloud.user.SSHKeyPairVO;
import com.cloud.user.User;
import com.cloud.user.dao.AccountDao;
import com.cloud.user.dao.SSHKeyPairDao;
import com.cloud.uservm.UserVm;
import com.cloud.utils.Pair;
import com.cloud.utils.component.ComponentContext;
import com.cloud.utils.component.ManagerBase;
import com.cloud.utils.db.Filter;
import com.cloud.utils.db.Transaction;
import com.cloud.utils.db.TransactionCallback;
import com.cloud.utils.db.TransactionCallbackWithException;
import com.cloud.utils.db.TransactionStatus;
import com.cloud.utils.net.Ip;
import com.cloud.vm.Nic;
import com.cloud.vm.ReservationContext;
import com.cloud.vm.ReservationContextImpl;
import com.cloud.vm.UserVmService;
import com.cloud.vm.UserVmVO;
import com.cloud.vm.VirtualMachine;
import com.cloud.vm.VMInstanceVO;
import com.cloud.vm.dao.UserVmDao;
import com.cloud.vm.dao.VMInstanceDao;
import com.cloud.offering.ServiceOffering;
import com.cloud.template.VirtualMachineTemplate;
import com.cloud.user.Account;
import com.cloud.utils.db.GlobalLock;
import com.cloud.utils.fsm.StateMachine2;
import com.cloud.utils.fsm.NoTransitionException;
import org.apache.cloudstack.acl.ControlledEntity;
import org.apache.cloudstack.acl.SecurityChecker;
import org.apache.cloudstack.api.ApiErrorCode;
import org.apache.cloudstack.api.BaseCmd;
import org.apache.cloudstack.api.ServerApiException;
import org.apache.cloudstack.api.command.user.containercluster.CreateContainerClusterCmd;
import org.apache.cloudstack.api.command.user.containercluster.DeleteContainerClusterCmd;
import org.apache.cloudstack.api.command.user.containercluster.ListContainerClusterCmd;
import org.apache.cloudstack.api.command.user.containercluster.StartContainerClusterCmd;
import org.apache.cloudstack.api.command.user.containercluster.StopContainerClusterCmd;
import org.apache.cloudstack.api.command.user.firewall.CreateFirewallRuleCmd;
import org.apache.cloudstack.api.command.user.vm.StartVMCmd;
import org.apache.cloudstack.api.response.ContainerClusterResponse;
import org.apache.cloudstack.api.response.ListResponse;
import org.apache.cloudstack.context.CallContext;
import org.apache.cloudstack.engine.orchestration.service.NetworkOrchestrationService;
import org.apache.cloudstack.framework.config.dao.ConfigurationDao;
import org.apache.cloudstack.managed.context.ManagedContextRunnable;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.ejb.Local;
import javax.inject.Inject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.security.SecureRandom;
import com.cloud.utils.concurrency.NamedThreadFactory;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.naming.ConfigurationException;
import java.util.concurrent.ConcurrentHashMap;

@Local(value = {ContainerClusterManager.class})
public class ContainerClusterManagerImpl extends ManagerBase implements ContainerClusterManager, ContainerClusterService {

    private static final Logger s_logger = Logger.getLogger(ContainerClusterManagerImpl.class);

    protected StateMachine2<ContainerCluster.State, ContainerCluster.Event, ContainerCluster> _stateMachine = ContainerCluster.State.getStateMachine();

    ScheduledExecutorService _gcExecutor;
    ScheduledExecutorService _stateScanner;

    @Inject
    protected ContainerClusterDao _containerClusterDao;
    @Inject
    protected ContainerClusterVmMapDao _clusterVmMapDao;
    @Inject
    protected ContainerClusterDetailsDao _containerClusterDetailsDao;
    @Inject
    protected SSHKeyPairDao _sshKeyPairDao;
    @Inject
    protected UserVmService _userVmService;
    @Inject
    protected DataCenterDao _dcDao;
    @Inject
    protected ServiceOfferingDao _offeringDao;
    @Inject
    protected VMTemplateDao _templateDao;
    @Inject
    protected AccountDao _accountDao;
    @Inject
    protected UserVmDao _vmDao;
    @Inject
    protected ConfigurationDao _globalConfigDao;
    @Inject
    protected NetworkService _networkService;
    @Inject
    protected NetworkOfferingDao _networkOfferingDao;
    @Inject
    protected NetworkModel _networkModel;
    @Inject
    protected PhysicalNetworkDao _physicalNetworkDao;
    @Inject
    protected NetworkOrchestrationService _networkMgr;
    @Inject
    protected NetworkDao _networkDao;
    @Inject
    protected IPAddressDao _publicIpAddressDao;
    @Inject
    protected PortForwardingRulesDao _portForwardingDao;
    @Inject
    private FirewallService _firewallService;
    @Inject
    protected RulesService _rulesService;
    @Inject
    private NetworkOfferingServiceMapDao _ntwkOfferingServiceMapDao;
    @Inject
    protected AccountManager _accountMgr;
    @Inject
    protected ContainerClusterVmMapDao _containerClusterVmMapDao;
    @Inject
    protected ServiceOfferingDao _srvOfferingDao;
    @Inject
    protected UserVmDao _userVmDao;
    @Inject
    private VMInstanceDao _vmInstanceDao;
    @Inject
    private VMTemplateZoneDao _templateZoneDao;
    @Inject
    protected CapacityManager _capacityMgr;
    @Inject
    protected ResourceManager _resourceMgr;
    @Inject
    protected ClusterDetailsDao _clusterDetailsDao;
    @Inject
    protected ClusterDao _clusterDao;

    @Override
    public ContainerCluster findById(final Long id) {
        return _containerClusterDao.findById(id);
    }

    @Override
    public ContainerCluster createContainerCluster(final String name,
                                                   final String displayName,
                                                   final Long zoneId,
                                                   final Long serviceOfferingId,
                                                   final Account owner,
                                                   final Long networkId,
                                                   final String sshKeyPair,
                                                   final Long clusterSize,
                                                   final String dockerRegistryUserName,
                                                   final String dockerRegistryPassword,
                                                   final String dockerRegistryUrl,
                                                   final String dockerRegistryEmail)
            throws InsufficientCapacityException, ResourceAllocationException, ManagementServerException {

        if (name == null || name.isEmpty()) {
            throw new InvalidParameterValueException("Invalid name for the container cluster name:" + name);
        }

        if (clusterSize < 1 || clusterSize > 100) {
            throw new InvalidParameterValueException("invalid cluster size " + clusterSize);
        }

        DataCenter zone =  _dcDao.findById(zoneId);
        if (zone == null) {
            throw new InvalidParameterValueException("Unable to find zone by id:" + zoneId);
        }

        if (Grouping.AllocationState.Disabled == zone.getAllocationState()) {
            throw new PermissionDeniedException("Cannot perform this operation, Zone:" + zone.getId() + " is currently disabled.");
        }

        ServiceOffering serviceOffering = _srvOfferingDao.findById(serviceOfferingId);
        if (serviceOffering == null) {
            throw new InvalidParameterValueException("No service offering with id:" + serviceOfferingId);
        }

        if(sshKeyPair != null && !sshKeyPair.isEmpty()) {
            SSHKeyPairVO sshkp = _sshKeyPairDao.findByName(owner.getAccountId(), owner.getDomainId(), sshKeyPair);
            if (sshkp == null) {
                throw new InvalidParameterValueException("Given SSH key pair with name:" + sshKeyPair + " was not found for the account " + owner.getAccountName());
            }
        }

        if (!isContainerServiceConfigured(zone)) {
            throw new ManagementServerException("Container service has not been configured properly to provision container clusters.");
        }

        VMTemplateVO template = _templateDao.findByTemplateName(_globalConfigDao.getValue(CcsConfig.ContainerClusterTemplateName.key()));
        List<VMTemplateZoneVO> listZoneTemplate = _templateZoneDao.listByZoneTemplate(zone.getId(), template.getId());
        if (listZoneTemplate == null || listZoneTemplate.isEmpty()) {
            s_logger.warn("The template:" + template.getId() + " is not available for use in zone:" + zoneId + " to provision container cluster name:" + name);
            throw new ManagementServerException("Container service has not been configured properly to provision container clusters.");
        }

        if (!validateServiceOffering(_srvOfferingDao.findById(serviceOfferingId))) {
            throw new InvalidParameterValueException("This service offering is not suitable for k8s cluster, service offering id is " + networkId);
        }

        validateDockerRegistryParams(dockerRegistryUserName, dockerRegistryPassword, dockerRegistryUrl, dockerRegistryEmail);

        plan(clusterSize, zoneId, _srvOfferingDao.findById(serviceOfferingId));

        Network network = null;
        if (networkId != null) {
            if (_containerClusterDao.listByNetworkId(networkId).isEmpty()) {
                network = _networkService.getNetwork(networkId);
                if (network == null) {
                    throw new InvalidParameterValueException("Unable to find network by ID " + networkId);
                }
                if (!validateNetwork(network)){
                    throw new InvalidParameterValueException("This network is not suitable for k8s cluster, network id is " + networkId);
                }
                _networkModel.checkNetworkPermissions(owner, network);
            }
            else {
                throw new InvalidParameterValueException("This network is already under use by another k8s cluster, network id is " + networkId);
            }
        } else { // user has not specified network in which cluster VM's to be provisioned, so create a network for container cluster
            NetworkOfferingVO networkOffering = _networkOfferingDao.findByUniqueName(
                    _globalConfigDao.getValue(CcsConfig.ContainerClusterNetworkOffering.key()));

            long physicalNetworkId = _networkModel.findPhysicalNetworkId(zone.getId(), networkOffering.getTags(), networkOffering.getTrafficType());
            PhysicalNetwork physicalNetwork = _physicalNetworkDao.findById(physicalNetworkId);

            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Creating network for account " + owner + " from the network offering id=" +
                        networkOffering.getId() + " as a part of cluster: " + name + " deployment process");
            }

            try {
                network = _networkMgr.createGuestNetwork(networkOffering.getId(), name + "-network", owner.getAccountName() + "-network",
                        null, null, null, null, owner, null, physicalNetwork, zone.getId(), ControlledEntity.ACLType.Account, null, null, null, null, true, null);
            } catch(Exception e) {
                s_logger.warn("Unable to create a network for the container cluster due to " + e);
                throw new ManagementServerException("Unable to create a network for the container cluster.");
            }
        }

        final Network defaultNetwork = network;
        final VMTemplateVO finalTemplate = template;
        final long cores = serviceOffering.getCpu() * clusterSize;
        final long memory = serviceOffering.getRamSize() * clusterSize;

        final ContainerClusterVO cluster = Transaction.execute(new TransactionCallback<ContainerClusterVO>() {
            @Override
            public ContainerClusterVO doInTransaction(TransactionStatus status) {
                ContainerClusterVO newCluster = new ContainerClusterVO(name, displayName, zoneId,
                        serviceOfferingId, finalTemplate.getId(), defaultNetwork.getId(), owner.getDomainId(),
                        owner.getAccountId(), clusterSize, ContainerCluster.State.Created, sshKeyPair, cores, memory, "", "");
                _containerClusterDao.persist(newCluster);
                return newCluster;
            }
        });

        Transaction.execute(new TransactionCallback<ContainerClusterDetailsVO>() {
            @Override
            public ContainerClusterDetailsVO doInTransaction(TransactionStatus status) {
                ContainerClusterDetailsVO clusterDetails = new ContainerClusterDetailsVO();
                clusterDetails.setClusterId(cluster.getId());
                clusterDetails.setRegistryUsername(dockerRegistryUserName);
                clusterDetails.setRegistryPassword(dockerRegistryPassword);
                clusterDetails.setRegistryUrl(dockerRegistryUrl);
                clusterDetails.setRegistryEmail(dockerRegistryEmail);
                clusterDetails.setUsername("admin");
                SecureRandom random = new SecureRandom();
                String randomPassword = new BigInteger(130, random).toString(32);
                clusterDetails.setPassword(randomPassword);
                _containerClusterDetailsDao.persist(clusterDetails);
                return clusterDetails;
            }
        });

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("A container cluster name:" + name + " id:" + cluster.getId() + " has been created.");
        }

        return cluster;
    }


    // Start operation can be performed at two diffrent life stages of container cluster. First when a freshly created cluster
    // in which case there are no resources provisisioned for the container cluster. So during start all the resources
    // are provisioned from scratch. Second kind of start, happens on  Stopped container cluster, in which all resources
    // are provisioned (like volumes, nics, networks etc). It just that VM's are not in running state. So just
    // start the VM's (which can possibly implicitly start the network also).
    @Override
    public boolean startContainerCluster(long containerClusterId, boolean onCreate) throws ManagementServerException,
            ResourceAllocationException, ResourceUnavailableException, InsufficientCapacityException {

        if (onCreate) {
            // Start for container cluster in 'Created' state
            return startContainerClusterOnCreate(containerClusterId);
        } else {
            // Start for container cluster in 'Stopped' state. Resources are already provisioned, just need to be started
            return startStoppedContainerCluster(containerClusterId);
        }
    }

    // perform a cold start (which will provision resources as well)
    private boolean startContainerClusterOnCreate(long containerClusterId) throws ManagementServerException {

        // Starting a contriner cluster has below workflow
        //   - start the newtwork
        //   - provision the master /node VM
        //   - priovision node VM's (as many as cluster size)
        //   - update the booke keeping data of the VM's provisioned for the cluster
        //   - setup networking (add Firewall and PF rules)
        //   - wait till kubernetes API server on master VM to come up
        //   - wait till addon services (dashboard etc) to come up
        //   - update API and dashboard URL endpoints in container cluster details

        ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Starting container cluster: " + containerCluster.getName());
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.StartRequested);

        Account account = _accountDao.findById(containerCluster.getAccountId());

        final DeployDestination dest = null;
        try {
            dest = plan(containerClusterId, containerCluster.getZoneId());
        }
        catch (InsufficientCapacityException e){
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            s_logger.warn("Provisioning the cluster failed due to insufficient capacity in the container cluster: " + containerCluster.getName() + " due to " + e);
            throw new ManagementServerException("Provisioning the cluster failed due to insufficient capacity in the container cluster: " + containerCluster.getName(), e);
        }
        final ReservationContext context = new ReservationContextImpl(null, null, null, account);

        try {
            _networkMgr.startNetwork(containerCluster.getNetworkId(), dest, context);
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Network:" + containerCluster.getNetworkId() + " is started for the  container cluster: " + containerCluster.getName());
            }
        } catch (RuntimeException e) {
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            s_logger.warn("Starting the network failed as part of starting container cluster " + containerCluster.getName() + " due to " + e);
            throw new ManagementServerException("Failed to start the network while creating container cluster name:" + containerCluster.getName(), e);
        } catch(Exception e) {
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            s_logger.warn("Starting the network failed as part of starting container cluster " + containerCluster.getName() + " due to " + e);
            throw new ManagementServerException("Failed to start the network while creating container cluster name:" + containerCluster.getName(), e);
        }

        IPAddressVO publicIp = null;
        List<IPAddressVO> ips = _publicIpAddressDao.listByAssociatedNetwork(containerCluster.getNetworkId(), true);
        if (ips == null || ips.isEmpty()) {
            s_logger.warn("Network:" + containerCluster.getNetworkId() + " for the container cluster name:" + containerCluster.getName() + " does not have " +
                    "public IP's assocated with it. So aborting container cluster strat.");
            throw new ManagementServerException("Failed to start the network while creating container cluster name:" + containerCluster.getName());
        }
        publicIp = ips.get(0);

        UserVm k8sMasterVM = null;
        try {
            k8sMasterVM = createK8SMaster(containerCluster);
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Provisioned the master VM's in to the container cluster name:" + containerCluster.getName());
            }
        } catch (RuntimeException e) {
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            s_logger.warn("Provisioning the master VM' failed in the container cluster: " + containerCluster.getName() + " due to " + e);
            throw new ManagementServerException("Provisioning the master VM' failed in the container cluster: " + containerCluster.getName(), e);
        } catch (Exception e) {
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            s_logger.warn("Provisioning the master VM' failed in the container cluster: " + containerCluster.getName() + " due to " + e);
            throw new ManagementServerException("Provisioning the master VM' failed in the container cluster: " + containerCluster.getName(), e);
        }

        final long clusterId = containerCluster.getId();
        final long masterVmId = k8sMasterVM.getId();
        Transaction.execute(new TransactionCallback<ContainerClusterVmMapVO>() {
            @Override
            public ContainerClusterVmMapVO doInTransaction(TransactionStatus status) {
                ContainerClusterVmMapVO newClusterVmMap = new ContainerClusterVmMapVO(clusterId, masterVmId);
                _clusterVmMapDao.persist(newClusterVmMap);
                return newClusterVmMap;
            }
        });

        String masterIP = k8sMasterVM.getPrivateIpAddress();

        long anyNodeVmId = 0;
        UserVm k8anyNodeVM = null;
        for (int i=1; i <= containerCluster.getNodeCount(); i++) {
            UserVm vm = null;
            try {
                vm = createK8SNode(containerCluster, masterIP, i);
                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("Provisioned a node VM in to the container cluster: " + containerCluster.getName());
                }
            } catch (RuntimeException e) {
                stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
                s_logger.warn("Provisioning the node VM failed in the container cluster " + containerCluster.getName() + " due to " + e);
                throw new ManagementServerException("Provisioning the node VM failed in the container cluster " + containerCluster.getName(), e);
            } catch (Exception e) {
                stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
                s_logger.warn("Provisioning the node VM failed in the container cluster " + containerCluster.getName() + " due to " + e);
                throw new ManagementServerException("Provisioning the node VM failed in the container cluster " + containerCluster.getName(), e);
            }

            if (anyNodeVmId == 0) {
                anyNodeVmId = vm.getId();
                k8anyNodeVM = vm;
            }

            final long nodeVmId = vm.getId();
            ContainerClusterVmMapVO clusterNodeVmMap = Transaction.execute(new TransactionCallback<ContainerClusterVmMapVO>() {
                @Override
                public ContainerClusterVmMapVO doInTransaction(TransactionStatus status) {
                    ContainerClusterVmMapVO newClusterVmMap = new ContainerClusterVmMapVO(clusterId, nodeVmId);
                    _clusterVmMapDao.persist(newClusterVmMap);
                    return newClusterVmMap;
                }
            });
        }

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Container cluster : " + containerCluster.getName() + " VM's are successfully provisioned.");
        }

        setupContainerClusterNetworkRules(publicIp, account, containerClusterId, masterVmId);

        int retryCounter = 0;
        int maxRetries = 10;
        boolean k8sApiServerSetup = false;

        while (retryCounter < maxRetries) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(publicIp.getAddress().addr(), 443), 10000);
                k8sApiServerSetup = true;
                containerCluster = _containerClusterDao.findById(containerClusterId);
                containerCluster.setEndpoint("https://" + publicIp.getAddress() + "/");
                _containerClusterDao.update(containerCluster.getId(), containerCluster);
                break;
            } catch (IOException e) {
                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("Waiting for container cluster: " + containerCluster.getName() + " API endpoint to be available. retry: " + retryCounter + "/" + maxRetries);
                }
                try { Thread.sleep(50000); } catch (InterruptedException ex) {}
                retryCounter++;
            }
        }

        if (k8sApiServerSetup) {

            retryCounter = 0;
            maxRetries = 10;
            // Dashbaord service is a docker image downloaded at run time.
            // So wait for some time and check if dashbaord service is up running.
            while (retryCounter < maxRetries) {

                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("Waiting for dashboard service for the container cluster: " + containerCluster.getName()
                            + " to come up. Attempt: " + retryCounter + " of max retries " + maxRetries);
                }

                if (isAddOnServiceRunning(containerCluster.getId(), "kubernetes-dashboard")) {

                    stateTransitTo(containerClusterId, ContainerCluster.Event.OperationSucceeded);

                    containerCluster = _containerClusterDao.findById(containerClusterId);
                    containerCluster.setConsoleEndpoint("https://" + publicIp.getAddress() + "/api/v1/proxy/namespaces/kube-system/services/kubernetes-dashboard");
                    _containerClusterDao.update(containerCluster.getId(), containerCluster);

                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Container cluster name:" + containerCluster.getName() + " is successfully started");
                    }

                    return true;
                }

                try { Thread.sleep(30000);} catch (InterruptedException ex) {}
                retryCounter++;
            }
            s_logger.warn("Failed to setup container cluster " + containerCluster.getName() + " in usable state as" +
                    " unable to bring dashboard add on service up");
        } else {
            s_logger.warn("Failed to setup container cluster " + containerCluster.getName() + " in usable state as" +
                    " unable to bring the API server up");
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);

        throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR,
                "Failed to deploy container cluster: " + containerCluster.getId() + " as unable to setup up in usable state");
    }

    private boolean startStoppedContainerCluster(long containerClusterId) throws ManagementServerException,
            ResourceAllocationException, ResourceUnavailableException, InsufficientCapacityException {

        final ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);
        if (containerCluster == null) {
            throw new ManagementServerException("Failed to find container cluster id: " + containerClusterId);
        }

        if (containerCluster.getRemoved() != null) {
            throw new ManagementServerException("Container cluster id:" + containerClusterId + " is already deleted.");
        }

        if (containerCluster.getState().equals(ContainerCluster.State.Running) ){
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Container cluster id: " + containerClusterId + " is already Running.");
            }
            return true;
        }

        if (containerCluster.getState().equals(ContainerCluster.State.Starting) ){
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Container cluster id: " + containerClusterId + " is getting started.");
            }
            return true;
        }

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Starting container cluster: " + containerCluster.getName());
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.StartRequested);

        for (final ContainerClusterVmMapVO vmMapVO : _clusterVmMapDao.listByClusterId(containerClusterId)) {
            final UserVmVO vm = _userVmDao.findById(vmMapVO.getVmId());
            try {
                if (vm == null) {
                    stateTransitTo(containerClusterId, ContainerCluster.Event.OperationFailed);
                    throw new ManagementServerException("Failed to start all VMs in container cluster id: " + containerClusterId);
                }
                startK8SVM(vm, containerCluster);
            } catch (ServerApiException ex) {
                s_logger.warn("Failed to start VM in container cluster id:" + containerClusterId + " due to " + ex);
                // dont bail out here. proceed further to stop the reset of the VM's
            }
        }

        for (final ContainerClusterVmMapVO vmMapVO : _clusterVmMapDao.listByClusterId(containerClusterId)) {
            final UserVmVO vm = _userVmDao.findById(vmMapVO.getVmId());
            if (vm == null || !vm.getState().equals(VirtualMachine.State.Running)) {
                stateTransitTo(containerClusterId, ContainerCluster.Event.OperationFailed);
                throw new ManagementServerException("Failed to start all VMs in container cluster id: " + containerClusterId);
            }
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.OperationSucceeded);
        if (s_logger.isDebugEnabled()) {
            s_logger.debug(" Container cluster name:" + containerCluster.getName() + " is successfully started.");
        }
        return true;
    }

    // Open up  firewall port 443, secure port on which kubernetes API server is running. Also create portforwarding
    // rule to forward public IP traffic to master VM private IP
    private void setupContainerClusterNetworkRules(IPAddressVO publicIp, Account account, long containerClusterId,
                                                   long masterVmId) throws  ManagementServerException {

        ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);

        List<String> sourceCidrList = new ArrayList<String>();
        sourceCidrList.add("0.0.0.0/0");

        try {
            CreateFirewallRuleCmd rule = new CreateFirewallRuleCmd();
            rule = ComponentContext.inject(rule);

            Field addressField = rule.getClass().getDeclaredField("ipAddressId");
            addressField.setAccessible(true);
            addressField.set(rule, publicIp.getId());

            Field protocolField = rule.getClass().getDeclaredField("protocol");
            protocolField.setAccessible(true);
            protocolField.set(rule, "TCP");

            Field startPortField = rule.getClass().getDeclaredField("publicStartPort");
            startPortField.setAccessible(true);
            startPortField.set(rule, new Integer(443));

            Field endPortField = rule.getClass().getDeclaredField("publicEndPort");
            endPortField.setAccessible(true);
            endPortField.set(rule, new Integer(443));

            Field cidrField = rule.getClass().getDeclaredField("cidrlist");
            cidrField.setAccessible(true);
            cidrField.set(rule, sourceCidrList);

            _firewallService.createIngressFirewallRule(rule);
            _firewallService.applyIngressFwRules(publicIp.getId(), account);

            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Provisioned firewall rule to open up port 443 on " + publicIp.getAddress() +
                        " for cluster " + containerCluster.getName());
            }
        } catch (RuntimeException rte) {
            s_logger.warn("Failed to provision firewall rules for the container cluster: " + containerCluster.getName()
                    + " due to exception: " + getStackTrace(rte));
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            throw new ManagementServerException("Failed to provision firewall rules for the container " +
                    "cluster: " + containerCluster.getName(), rte);
        } catch (Exception e) {
            s_logger.warn("Failed to provision firewall rules for the container cluster: " + containerCluster.getName()
                    + " due to exception: " + getStackTrace(e));
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            throw new ManagementServerException("Failed to provision firewall rules for the container " +
                    "cluster: " + containerCluster.getName());
        }

        Nic masterVmNic = _networkModel.getNicInNetwork(masterVmId, containerCluster.getNetworkId());
        final Ip masterIpFinal = new Ip(masterVmNic.getIp4Address());
        final long publicIpId = publicIp.getId();
        final long networkId = containerCluster.getNetworkId();
        final long accountId = account.getId();
        final long domainId = account.getDomainId();
        final long masterVmIdFinal = masterVmId;

        try {
            PortForwardingRuleVO pfRule = Transaction.execute(new TransactionCallbackWithException<PortForwardingRuleVO, NetworkRuleConflictException>() {
                @Override
                public PortForwardingRuleVO doInTransaction(TransactionStatus status) throws NetworkRuleConflictException {
                    PortForwardingRuleVO newRule =
                            new PortForwardingRuleVO(null, publicIpId,
                                    443, 443,
                                    masterIpFinal,
                                    443, 443,
                                    "tcp", networkId, accountId, domainId, masterVmIdFinal);
                    newRule.setDisplay(true);
                    newRule.setState(FirewallRule.State.Add);
                    newRule = _portForwardingDao.persist(newRule);
                    return newRule;
                }
            });
            _rulesService.applyPortForwardingRules(publicIp.getId(), account);

            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Provisioning port forwarding rule from port 443 on " + publicIp.getAddress() +
                        " to the master VM IP :" + masterIpFinal + " in container cluster " + containerCluster.getName());
            }
        } catch (RuntimeException rte) {
            s_logger.warn("Failed to activate port forwarding rules for the container cluster " + containerCluster.getName() + " due to "  + rte);
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            throw new ManagementServerException("Failed to activate port forwarding rules for the cluster: " + containerCluster.getName(), rte);
        } catch (Exception e) {
            s_logger.warn("Failed to activate port forwarding rules for the container cluster " + containerCluster.getName() + " due to "  + e);
            stateTransitTo(containerClusterId, ContainerCluster.Event.CreateFailed);
            throw new ManagementServerException("Failed to activate port forwarding rules for the cluster: " + containerCluster.getName(), e);
        }
    }

    public boolean validateNetwork(Network network) {
        NetworkOffering nwkoff = _networkOfferingDao.findById(network.getNetworkOfferingId());
        if (nwkoff.isSystemOnly()){
            throw new InvalidParameterValueException("This network is for system use only, network id " + network.getId());
        }
        if (! _networkModel.areServicesSupportedInNetwork(network.getId(), Service.UserData)){
            throw new InvalidParameterValueException("This network does not support userdata that is required for k8s, network id " + network.getId());
        }
        if (! _networkModel.areServicesSupportedInNetwork(network.getId(), Service.Firewall)){
            throw new InvalidParameterValueException("This network does not support firewall that is required for k8s, network id " + network.getId());
        }
        if (! _networkModel.areServicesSupportedInNetwork(network.getId(), Service.PortForwarding)){
            throw new InvalidParameterValueException("This network does not support port forwarding that is required for k8s, network id " + network.getId());
        }
        if (! _networkModel.areServicesSupportedInNetwork(network.getId(), Service.Dhcp)){
            throw new InvalidParameterValueException("This network does not support dhcp that is required for k8s, network id " + network.getId());
        }
        return true;
    }

    public boolean validateServiceOffering(ServiceOffering offering) {
        final int cpu_requested = offering.getCpu() * offering.getSpeed();
        final int ram_requested = offering.getRamSize();
        if (offering.isDynamic()){
            throw new InvalidParameterValueException("This service offering is not suitable for k8s cluster as this is dynamic, service offering id is " + offering.getId());
        }
        if (ram_requested < 64){
            throw new InvalidParameterValueException("This service offering is not suitable for k8s cluster as this has less than 256M of Ram, service offering id is " +  offering.getId());
        }
        if( cpu_requested < 200) {
            throw new InvalidParameterValueException("This service offering is not suitable for k8s cluster as this has less than 600MHz of CPU, service offering id is " +  offering.getId());
        }
        return true;
    }

    private void validateDockerRegistryParams(final String dockerRegistryUserName,
                                                 final String dockerRegistryPassword,
                                                 final String dockerRegistryUrl,
                                                 final String dockerRegistryEmail) {
        // if no params related to docker registry specified then nothing to validate so return true
        if ((dockerRegistryUserName == null || dockerRegistryUserName.isEmpty()) &&
                (dockerRegistryPassword == null || dockerRegistryPassword.isEmpty())  &&
                (dockerRegistryUrl == null || dockerRegistryUrl.isEmpty()) &&
                (dockerRegistryEmail == null || dockerRegistryEmail.isEmpty())) {
            return;
        }

        // all params related to docker registry must be specified or nothing
        if (!((dockerRegistryUserName != null && !dockerRegistryUserName.isEmpty()) &&
                (dockerRegistryPassword != null && !dockerRegistryPassword.isEmpty()) &&
                (dockerRegistryUrl != null && !dockerRegistryUrl.isEmpty()) &&
                (dockerRegistryEmail != null && !dockerRegistryEmail.isEmpty()))) {
            throw new InvalidParameterValueException("All the docker private registry parameters (username, password, url, email) required are specified");
        }

        try {
            URL url = new URL(dockerRegistryUrl);
        } catch (MalformedURLException e) {
            throw new InvalidParameterValueException("Invalid docker registry url specified");
        }

        Pattern VALID_EMAIL_ADDRESS_REGEX = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX .matcher(dockerRegistryEmail);
        if (!matcher.find()) {
            throw new InvalidParameterValueException("Invalid docker registry email specified");
        }
    }

    public DeployDestination plan(final long clusterSize, final long dcId, final ServiceOffering offering) throws InsufficientServerCapacityException {
        final int cpu_requested = offering.getCpu() * offering.getSpeed();
        final long ram_requested = offering.getRamSize() * 1024L * 1024L;
        List<HostVO> hosts = _resourceMgr.listAllHostsInOneZoneByType(Type.Routing, dcId);
        final Map<String, Pair<HostVO, Integer>> hosts_with_resevered_capacity = new ConcurrentHashMap<String, Pair<HostVO, Integer>>();
        for (HostVO h : hosts) {
           hosts_with_resevered_capacity.put(h.getUuid(), new Pair<HostVO, Integer>(h, 0));
        }
        boolean suitable_host_found=false;
        for (int i=1; i <= clusterSize+1; i++) {
            suitable_host_found=false;
            for (Map.Entry<String, Pair<HostVO, Integer>> hostEntry : hosts_with_resevered_capacity.entrySet()) {
                Pair<HostVO, Integer> hp = hostEntry.getValue();
                HostVO h = hp.first();
                int reserved = hp.second();
                reserved++;
                ClusterVO cluster = _clusterDao.findById(h.getClusterId());
                ClusterDetailsVO cluster_detail_cpu = _clusterDetailsDao.findDetail(cluster.getId(), "cpuOvercommitRatio");
                ClusterDetailsVO cluster_detail_ram = _clusterDetailsDao.findDetail(cluster.getId(), "memoryOvercommitRatio");
                Float cpuOvercommitRatio = Float.parseFloat(cluster_detail_cpu.getValue());
                Float memoryOvercommitRatio = Float.parseFloat(cluster_detail_ram.getValue());
                if (s_logger.isDebugEnabled()){
                    s_logger.debug("Checking host " + h.getId() + " for capacity already reserved " + reserved);
                }
                if (_capacityMgr.checkIfHostHasCapacity(h.getId(), cpu_requested * reserved, ram_requested * reserved, false, cpuOvercommitRatio, memoryOvercommitRatio, true)) {
                    if (s_logger.isDebugEnabled()){
                        s_logger.debug("Found host " + h.getId() + " has enough capacity cpu = " + cpu_requested * reserved + " ram =" + ram_requested * reserved);
                    }
                    hostEntry.setValue(new Pair<HostVO, Integer>(h, reserved));
                    suitable_host_found = true;
                    break;
                }
            }
            if (suitable_host_found){
                continue;
            }
            else {
                 if (s_logger.isDebugEnabled()){
                     s_logger.debug("Suitable hosts not found in datacenter " + dcId + " for node " + i);
                 }
                break;
            }
        }
        if (suitable_host_found){
            if (s_logger.isDebugEnabled()){
                s_logger.debug("Suitable hosts found in datacenter " + dcId + " creating deployment destination");
            }
            return new DeployDestination(_dcDao.findById(dcId), null, null, null);
        }
        s_logger.warn(String.format("Cannot find enough capacity for container_cluster(requested cpu=%1$s memory=%2$s)",
                cpu_requested*clusterSize, ram_requested*clusterSize));
        throw new InsufficientServerCapacityException(String.format("Cannot find enough capacity for container_cluster(requested cpu=%1$s memory=%2$s)",
                cpu_requested*clusterSize, ram_requested*clusterSize), DataCenter.class, dcId);
    }

    public DeployDestination plan(final long containerClusterId, final long dcId) throws InsufficientServerCapacityException {
        ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);
        ServiceOffering offering = _srvOfferingDao.findById(containerCluster.getServiceOfferingId());

        if (s_logger.isDebugEnabled()){
            s_logger.debug("Checking deployment destination for containerClusterId= " + containerClusterId + " in dcId=" + dcId);
        }

        return plan(containerCluster.getNodeCount() + 1, dcId, offering);
    }

    @Override
    public boolean stopContainerCluster(long containerClusterId) throws ManagementServerException {

        final ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);
        if (containerCluster == null) {
            throw new ManagementServerException("Failed to find container cluster id: " + containerClusterId);
        }

        if (containerCluster.getRemoved() != null) {
            throw new ManagementServerException("Container cluster id:" + containerClusterId + " is already deleted.");
        }

        if (containerCluster.getState().equals(ContainerCluster.State.Stopped) ){
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Container cluster id: " + containerClusterId + " is already stopped.");
            }
            return true;
        }

        if (containerCluster.getState().equals(ContainerCluster.State.Stopping) ){
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Container cluster id: " + containerClusterId + " is getting stopped.");
            }
            return true;
        }

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Stopping container cluster: " + containerCluster.getName());
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.StopRequested);

        for (final ContainerClusterVmMapVO vmMapVO : _clusterVmMapDao.listByClusterId(containerClusterId)) {
            final UserVmVO vm = _userVmDao.findById(vmMapVO.getVmId());
            try {
                if (vm == null) {
                    stateTransitTo(containerClusterId, ContainerCluster.Event.OperationFailed);
                    throw new ManagementServerException("Failed to start all VMs in container cluster id: " + containerClusterId);
                }
                stopK8SVM(vmMapVO);
            } catch (ServerApiException ex) {
                s_logger.warn("Failed to stop VM in container cluster id:" + containerClusterId + " due to " + ex);
                // dont bail out here. proceed further to stop the reset of the VM's
            }
        }

        for (final ContainerClusterVmMapVO vmMapVO : _clusterVmMapDao.listByClusterId(containerClusterId)) {
            final UserVmVO vm = _userVmDao.findById(vmMapVO.getVmId());
            if (vm == null || !vm.getState().equals(VirtualMachine.State.Stopped)) {
                stateTransitTo(containerClusterId, ContainerCluster.Event.OperationFailed);
                throw new ManagementServerException("Failed to stop all VMs in container cluster id: " + containerClusterId);
            }
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.OperationSucceeded);
        return true;
    }

    private boolean isAddOnServiceRunning(Long clusterId, String svcName) {

        ContainerClusterVO containerCluster = _containerClusterDao.findById(clusterId);

        //FIXME: whole logic needs revamp. Assumption that management server has public network access is not practical
        IPAddressVO publicIp = null;
        List<IPAddressVO> ips = _publicIpAddressDao.listByAssociatedNetwork(containerCluster.getNetworkId(), true);
        publicIp = ips.get(0);

        Runtime r = Runtime.getRuntime();
        int nodePort = 0;
        try {
            ContainerClusterDetailsVO clusterDetails = _containerClusterDetailsDao.findByClusterId(containerCluster.getId());
            String execStr = "kubectl -s https://" + publicIp.getAddress().addr() + "/ --username=admin "
                    + " --password=" + clusterDetails.getPassword()
                    + " get pods --insecure-skip-tls-verify=true --namespace=kube-system";
            Process p = r.exec(execStr);
            p.waitFor();
            BufferedReader b = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF8"));
            String line = "";
            while ((line = b.readLine()) != null) {
                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("KUBECTL : " + line);
                }
                if (line.contains(svcName) && line.contains("Running")) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Service :" + svcName + " for the container cluster "
                                + containerCluster.getName() + " is running");
                    }
                    b.close();
                    return true;
                }
            }
            b.close();
        } catch (IOException excep) {
            s_logger.warn("KUBECTL: " + excep);
        } catch (InterruptedException e) {
            s_logger.warn("KUBECTL: " + e);
        }
        return false;
    }

    @Override
    public boolean deleteContainerCluster(Long containerClusterId) throws ManagementServerException {

        ContainerClusterVO cluster = _containerClusterDao.findById(containerClusterId);
        if (cluster == null) {
            throw new InvalidParameterValueException("Invalid cluster id specified");
        }

        CallContext ctx = CallContext.current();
        Account caller = ctx.getCallingAccount();

        _accountMgr.checkAccess(caller, SecurityChecker.AccessType.OperateEntry, false, cluster);

        return cleanupContainerClusterResources(containerClusterId);
    }

    private boolean cleanupContainerClusterResources(Long containerClusterId) throws ManagementServerException {

        ContainerClusterVO cluster = _containerClusterDao.findById(containerClusterId);

        if (!(cluster.getState().equals(ContainerCluster.State.Running)
                || cluster.getState().equals(ContainerCluster.State.Stopped)
                || cluster.getState().equals(ContainerCluster.State.Alert)
                || cluster.getState().equals(ContainerCluster.State.Error)
                || cluster.getState().equals(ContainerCluster.State.Destroying))) {
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Cannot perform delete operation on cluster:" + cluster.getName() + " in state " + cluster.getState() );
            }
            throw new PermissionDeniedException("Cannot perform delete operation on cluster: " + cluster.getName() + " in state" + cluster.getState() );
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.DestroyRequested);

        boolean failedVmDestroy = false;
        List<ContainerClusterVmMapVO> clusterVMs = _containerClusterVmMapDao.listByClusterId(cluster.getId());
        if ( (clusterVMs != null) && !clusterVMs.isEmpty()) {
            for (ContainerClusterVmMapVO clusterVM: clusterVMs) {
                long vmID = clusterVM.getVmId();

                // delete only if VM exists and is not removed
                UserVmVO userVM = _vmDao.findById(vmID);
                if (userVM== null || userVM.isRemoved()) {
                    continue;
                }

                try {
                    _userVmService.destroyVm(vmID);
                    _userVmService.expungeVm(vmID);
                    _containerClusterVmMapDao.expunge(clusterVM.getId());
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Destroyed VM: " + userVM.getInstanceName() + " as part of cluster: " + cluster.getName() + " destroy.");
                    }
                } catch (Exception e ) {
                    failedVmDestroy = true;
                    s_logger.warn("Failed to destroy VM :" + userVM.getInstanceName() + " part of the cluster: " + cluster.getName() +
                            " due to " + e);
                    s_logger.warn("Moving on with destroying remaining resources provisioned for the cluster: " + cluster.getName());
                }
            }
        }

        // if there are VM's that were not expunged, we can not delete the network
        if(!failedVmDestroy) {
            NetworkVO network = null;
            try {
                network = _networkDao.findById(cluster.getNetworkId());
                if (network != null && network.getRemoved() == null) {
                    Account owner = _accountMgr.getAccount(network.getAccountId());
                    User callerUser = _accountMgr.getActiveUser(CallContext.current().getCallingUserId());
                    ReservationContext context = new ReservationContextImpl(null, null, callerUser, owner);
                    _networkMgr.destroyNetwork(cluster.getNetworkId(), context, true);
                    if(s_logger.isDebugEnabled()) {
                        s_logger.debug("Destroyed network: " +  network.getName() + " as part of cluster: " + cluster.getName() + " destroy");
                    }
                }
            } catch (Exception e) {
                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("Failed to destroy network: " + cluster.getNetworkId() +
                            " as part of cluster: " + cluster.getName() + "  destroy due to " + e);
                }
                stateTransitTo(containerClusterId, ContainerCluster.Event.OperationFailed);
                cluster = _containerClusterDao.findById(containerClusterId);
                cluster.setCheckForGc(true);
                _containerClusterDao.update(cluster.getId(), cluster);

                throw new ManagementServerException("Failed to delete the network as part of container cluster name:" + cluster.getName() + " clean up");
            }
        } else {
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Not deleting the network as there are VM's that are not expunged in container cluster " + cluster.getName());
            }
            stateTransitTo(containerClusterId, ContainerCluster.Event.OperationFailed);
            cluster = _containerClusterDao.findById(containerClusterId);
            cluster.setCheckForGc(true);
            _containerClusterDao.update(cluster.getId(), cluster);

            throw new ManagementServerException("Failed to destroy one or more VM's as part of container cluster name:" + cluster.getName() + " clean up");
        }

        stateTransitTo(containerClusterId, ContainerCluster.Event.OperationSucceeded);

        cluster = _containerClusterDao.findById(containerClusterId);
        cluster.setCheckForGc(false);
        _containerClusterDao.update(cluster.getId(), cluster);

        _containerClusterDao.remove(cluster.getId());

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Container cluster name:" + cluster.getName() + " is successfully deleted");
        }

        return true;
    }


    UserVm createK8SMaster(final ContainerClusterVO containerCluster) throws ManagementServerException,
            ResourceAllocationException, ResourceUnavailableException, InsufficientCapacityException {

        UserVm masterVm = null;

        DataCenter zone = _dcDao.findById(containerCluster.getZoneId());
        ServiceOffering serviceOffering = _offeringDao.findById(containerCluster.getServiceOfferingId());
        VirtualMachineTemplate template = _templateDao.findById(containerCluster.getTemplateId());

        List<Long> networkIds = new ArrayList<Long>();
        networkIds.add(containerCluster.getNetworkId());

        Account owner = _accountDao.findById(containerCluster.getAccountId());

        Network.IpAddresses addrs = new Network.IpAddresses(null, null);

        Map<String, String> customparameterMap = new HashMap<String, String>();

        String hostName = containerCluster.getName() + "-k8s-master";

        String k8sMasterConfig = null;
        try {
            String masterCloudConfig = _globalConfigDao.getValue(CcsConfig.ContainerClusterMasterCloudConfig.key());
            k8sMasterConfig = readFile(masterCloudConfig);
            ContainerClusterDetailsVO clusterDetails = _containerClusterDetailsDao.findByClusterId(containerCluster.getId());
            final String password = "{{ k8s_master.password }}";
            final String user = "{{ k8s_master.user }}";
            k8sMasterConfig = k8sMasterConfig.replace(password, clusterDetails.getPassword());
            k8sMasterConfig = k8sMasterConfig.replace(user, clusterDetails.getUserName());
        } catch (RuntimeException e ) {
            s_logger.error("Failed to read kubernetes master configuration file due to " + e);
            throw new ManagementServerException("Failed to read kubernetes master configuration file", e);
        } catch (Exception e) {
            s_logger.error("Failed to read kubernetes master configuration file due to " + e);
            throw new ManagementServerException("Failed to read kubernetes master configuration file", e);
        }

        String base64UserData = Base64.encodeBase64String(k8sMasterConfig.getBytes(Charset.forName("UTF-8")));

        masterVm = _userVmService.createAdvancedVirtualMachine(zone, serviceOffering, template, networkIds, owner,
                hostName, containerCluster.getDescription(), null, null, null,
                null, BaseCmd.HTTPMethod.POST, base64UserData, containerCluster.getKeyPair(),
                null, addrs, null, null, null, customparameterMap, null);

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Created master VM: " + hostName + " in the container cluster: " + containerCluster.getName());
        }

        startK8SVM(masterVm, containerCluster);

        masterVm = _vmDao.findById(masterVm.getId());
        return masterVm;
    }


    UserVm createK8SNode(ContainerClusterVO containerCluster, String masterIp, int nodeInstance) throws ManagementServerException,
            ResourceAllocationException, ResourceUnavailableException, InsufficientCapacityException {

        UserVm nodeVm = null;

        DataCenter zone = _dcDao.findById(containerCluster.getZoneId());
        ServiceOffering serviceOffering = _offeringDao.findById(containerCluster.getServiceOfferingId());
        VirtualMachineTemplate template = _templateDao.findById(containerCluster.getTemplateId());

        List<Long> networkIds = new ArrayList<Long>();
        networkIds.add(containerCluster.getNetworkId());

        Account owner = _accountDao.findById(containerCluster.getAccountId());

        Network.IpAddresses addrs = new Network.IpAddresses(null, null);

        Map<String, String> customparameterMap = new HashMap<String, String>();

        String hostName = containerCluster.getName() + "-k8s-node-" + String.valueOf(nodeInstance);

        String k8sNodeConfig = null;
        try {
            String nodeCloudConfig = _globalConfigDao.getValue(CcsConfig.ContainerClusterNodeCloudConfig.key());
            k8sNodeConfig = readFile(nodeCloudConfig).toString();
            String masterIPString = "{{ k8s_master.default_ip }}";
            k8sNodeConfig = k8sNodeConfig.replace(masterIPString, masterIp);

            ContainerClusterDetailsVO clusterDetails = _containerClusterDetailsDao.findByClusterId(containerCluster.getId());

            /* genarate /.docker/config.json file on the nodes only if container cluster is created to
             * use docker private registry */
            String dockerUserName = clusterDetails.getRegistryUsername();
            String dockerPassword = clusterDetails.getRegistryPassword();
            if (dockerUserName != null && !dockerUserName.isEmpty() && dockerPassword != null && !dockerPassword.isEmpty()) {
                // do write file for  /.docker/config.json through the code instead of k8s-node.yml as we can no make a section
                // optional or conditionally applied
                String dockerConfigString = "write-files:\n" +
                        "  - path: /.docker/config.json\n" +
                        "    owner: core:core\n" +
                        "    permissions: '0644'\n" +
                        "    content: |\n" +
                        "      {\n" +
                        "        \"auths\": {\n" +
                        "          {{docker.url}}: {\n" +
                        "            \"auth\": {{docker.secret}},\n" +
                        "            \"email\": {{docker.email}}\n" +
                        "          }\n" +
                        "         }\n" +
                        "      }";
                k8sNodeConfig = k8sNodeConfig.replace("write-files:", dockerConfigString);
                String dockerUrl = "{{docker.url}}";
                String dockerAuth = "{{docker.secret}}";
                String dockerEmail = "{{docker.email}}";
                String usernamePassword = dockerUserName + ":" + dockerPassword;
                String base64Auth = Base64.encodeBase64String(usernamePassword.getBytes(Charset.forName("UTF-8")));
                k8sNodeConfig = k8sNodeConfig.replace(dockerUrl, "\"" + clusterDetails.getRegistryUrl() + "\"");
                k8sNodeConfig = k8sNodeConfig.replace(dockerAuth, "\"" + base64Auth + "\"");
                k8sNodeConfig = k8sNodeConfig.replace(dockerEmail, "\"" + clusterDetails.getRegistryEmail() + "\"");
            }
        } catch (RuntimeException e ) {
            s_logger.warn("Failed to read node configuration file due to " + e );
            throw new ManagementServerException("Failed to read cluster node configuration file.", e);
        } catch (Exception e) {
            s_logger.warn("Failed to read node configuration file due to " + e );
            throw new ManagementServerException("Failed to read cluster node configuration file.", e);
        }

        String base64UserData = Base64.encodeBase64String(k8sNodeConfig.getBytes(Charset.forName("UTF-8")));

        nodeVm = _userVmService.createAdvancedVirtualMachine(zone, serviceOffering, template, networkIds, owner,
                hostName, containerCluster.getDescription(), null, null, null,
                null, BaseCmd.HTTPMethod.POST, base64UserData, containerCluster.getKeyPair(),
                null, addrs, null, null, null, customparameterMap, null);

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Created cluster node VM: " + hostName + " in the container cluster: " + containerCluster.getName());
        }

        startK8SVM(nodeVm, containerCluster);

        nodeVm = _vmDao.findById(nodeVm.getId());
        return nodeVm;
    }

    private void startK8SVM(final UserVm vm, final ContainerClusterVO containerCluster) throws ServerApiException {

        try {
            StartVMCmd startVm = new StartVMCmd();
            startVm = ComponentContext.inject(startVm);
            Field f = startVm.getClass().getDeclaredField("id");
            f.setAccessible(true);
            f.set(startVm, vm.getId());
            _userVmService.startVirtualMachine(startVm);
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Started VM in the container cluster: " + containerCluster.getName());
            }
        } catch (ConcurrentOperationException ex) {
            s_logger.warn("Failed to start VM in the container cluster name:" + containerCluster.getName() + " due to Exception: " , ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to start VM in the container cluster name:" + containerCluster.getName(), ex);
        } catch (ResourceUnavailableException ex) {
            s_logger.warn("Failed to start VM in the container cluster name:" + containerCluster.getName() + " due to Exception: " , ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to start VM in the container cluster name:" + containerCluster.getName(), ex);
        } catch (InsufficientCapacityException ex) {
            s_logger.warn("Failed to start VM in the container cluster name:" + containerCluster.getName() + " due to Exception: " , ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to start VM in the container cluster name:" + containerCluster.getName(), ex);
        } catch (RuntimeException ex) {
            s_logger.warn("Failed to start VM in the container cluster name:" + containerCluster.getName() + " due to Exception: " , ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to start VM in the container cluster name:" + containerCluster.getName(), ex);
        } catch (Exception ex) {
            s_logger.warn("Failed to start VM in the container cluster name:" + containerCluster.getName() + " due to Exception: " , ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to start VM in the container cluster name:" + containerCluster.getName(), ex);
        }

        UserVm startVm = _vmDao.findById(vm.getId());
        if (!startVm.getState().equals(VirtualMachine.State.Running)) {
            s_logger.warn("Failed to start VM instance.");
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to start VM instance in container cluster " + containerCluster.getName());
        }
    }

    private void stopK8SVM(final ContainerClusterVmMapVO vmMapVO) throws ServerApiException {
        try {
            _userVmService.stopVirtualMachine(vmMapVO.getVmId(), false);
        } catch (ConcurrentOperationException ex) {
            s_logger.warn("Failed to stop container cluster VM due to Exception: ", ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, ex.getMessage());
        }
    }

    @Override
    public ListResponse<ContainerClusterResponse>  listContainerClusters(ListContainerClusterCmd cmd) {

        CallContext ctx = CallContext.current();
        Account caller = ctx.getCallingAccount();

        ListResponse<ContainerClusterResponse> response = new ListResponse<ContainerClusterResponse>();

        List<ContainerClusterResponse> responsesList = new ArrayList<ContainerClusterResponse>();

        if (cmd.getId() != null) {
            ContainerClusterVO cluster = _containerClusterDao.findById(cmd.getId());
            if (cluster == null) {
                throw new InvalidParameterValueException("Invalid cluster id specified");
            }

            _accountMgr.checkAccess(caller, SecurityChecker.AccessType.ListEntry, false, cluster);

            responsesList.add(createContainerClusterResponse(cmd.getId()));
        } else {
            if (_accountMgr.isAdmin(caller.getId())) {

                Filter searchFilter = new Filter(ContainerClusterVO.class, "id", true, cmd.getStartIndex(), cmd.getPageSizeVal());
                List<ContainerClusterVO> containerClusters = _containerClusterDao.listAll(searchFilter);
                for (ContainerClusterVO cluster : containerClusters) {
                    ContainerClusterResponse clusterReponse = createContainerClusterResponse(cluster.getId());
                    responsesList.add(clusterReponse);
                }
            } else {
                List<ContainerClusterVO> containerClusters = _containerClusterDao.listByAccount(caller.getAccountId());
                for (ContainerClusterVO cluster : containerClusters) {
                    ContainerClusterResponse clusterReponse = createContainerClusterResponse(cluster.getId());
                    responsesList.add(clusterReponse);
                }
            }

        }
        response.setResponses(responsesList);
        return response;
    }

    public ContainerClusterResponse createContainerClusterResponse(long containerClusterId) {

        ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);
        ContainerClusterResponse response = new ContainerClusterResponse();

        response.setId(containerCluster.getUuid());

        response.setName(containerCluster.getName());

        response.setDescription(containerCluster.getDescription());

        DataCenterVO zone = ApiDBUtils.findZoneById(containerCluster.getZoneId());
        response.setZoneId(zone.getUuid());
        response.setZoneName(zone.getName());

        response.setClusterSize(String.valueOf(containerCluster.getNodeCount()));

        VMTemplateVO template = ApiDBUtils.findTemplateById(containerCluster.getTemplateId());
        response.setTemplateId(template.getUuid());

        ServiceOfferingVO offering = _srvOfferingDao.findById(containerCluster.getServiceOfferingId());
        response.setServiceOfferingId(offering.getUuid());

        response.setServiceOfferingName(offering.getName());

        response.setKeypair(containerCluster.getKeyPair());

        response.setState(containerCluster.getState().toString());

        response.setCores(String.valueOf(containerCluster.getCores()));

        response.setMemory(String.valueOf(containerCluster.getMemory()));

        response.setObjectName("containercluster");

        NetworkVO ntwk = _networkDao.findByIdIncludingRemoved(containerCluster.getNetworkId());

        response.setEndpoint(containerCluster.getEndpoint());

        response.setNetworkId(ntwk.getUuid());

        response.setAssociatedNetworkName(ntwk.getName());

        response.setConsoleEndpoint(containerCluster.getConsoleEndpoint());

        List<String> vmIds = new ArrayList<String>();
        List<ContainerClusterVmMapVO> vmList = _containerClusterVmMapDao.listByClusterId(containerCluster.getId());
        if (vmList != null && !vmList.isEmpty()) {
            for (ContainerClusterVmMapVO vmMapVO: vmList) {
                UserVmVO userVM = _userVmDao.findById(vmMapVO.getVmId());
                if (userVM != null) {
                    vmIds.add(userVM.getUuid());
                }
            }
        }

        response.setVirtualMachineIds(vmIds);

        ContainerClusterDetailsVO clusterDetails = _containerClusterDetailsDao.findByClusterId(containerCluster.getId());
        if (clusterDetails != null) {
            response.setUsername(clusterDetails.getUserName());
            response.setPassword(clusterDetails.getPassword());
        }

        return response;
    }

    static String readFile(String path) throws IOException
    {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, StandardCharsets.UTF_8);
    }

    protected boolean stateTransitTo(long containerClusterId, ContainerCluster.Event e) {
        ContainerClusterVO containerCluster = _containerClusterDao.findById(containerClusterId);
        try {
            return _stateMachine.transitTo(containerCluster, e, null, _containerClusterDao);
        } catch (NoTransitionException nte) {
            s_logger.warn("Failed to transistion state of the container cluster: " + containerCluster.getName()
                    + " in state " + containerCluster.getState().toString() + " on event " + e.toString());
            return false;
        }
    }

    private static String getStackTrace(final Throwable throwable) {
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw, true);
        throwable.printStackTrace(pw);
        return sw.getBuffer().toString();
    }

    private boolean isContainerServiceConfigured(DataCenter zone) {

        String templateName = _globalConfigDao.getValue(CcsConfig.ContainerClusterTemplateName.key());
        if (templateName == null || templateName.isEmpty()) {
            s_logger.warn("Global setting " + CcsConfig.ContainerClusterTemplateName.key() + " is empty." +
                    "Template name need to be specified, for container service to function.");
            return false;
        }

        final VMTemplateVO template = _templateDao.findByTemplateName(templateName);
        if (template == null) {
           s_logger.warn("Unable to find the template:" + templateName  + " to be used for provisioning cluster");
            return false;
        }

        String masterCloudConfig = _globalConfigDao.getValue(CcsConfig.ContainerClusterMasterCloudConfig.key());
        if (masterCloudConfig == null || masterCloudConfig.isEmpty()) {
            s_logger.warn("global setting " + CcsConfig.ContainerClusterMasterCloudConfig.key() + " is empty." +
                    "Admin has not specified the cloud config template to be used for provisioning master VM");
            return false;
        }

        String nodeCloudConfig = _globalConfigDao.getValue(CcsConfig.ContainerClusterNodeCloudConfig.key());
        if (nodeCloudConfig == null || nodeCloudConfig.isEmpty()) {
            s_logger.warn("global setting " + CcsConfig.ContainerClusterNodeCloudConfig.key() + " is empty." +
                    "Admin has not specified the cloud config template to be used for provisioning node VM's");
            return false;
        }


        String networkOfferingName = _globalConfigDao.getValue(CcsConfig.ContainerClusterNetworkOffering.key());
        if (networkOfferingName == null || networkOfferingName.isEmpty()) {
            s_logger.warn("global setting " + CcsConfig.ContainerClusterNetworkOffering.key()  + " is empty. " +
                    "Admin has not yet specified the network offering to be used for provisioning isolated network for the cluster.");
            return false;
        }

        NetworkOfferingVO networkOffering = _networkOfferingDao.findByUniqueName(networkOfferingName);
        if (networkOffering == null) {
            s_logger.warn("Network offering with name :" + networkOfferingName + " specified by admin is not found.");
            return false;
        }

        if (networkOffering.getState() == NetworkOffering.State.Disabled) {
            s_logger.warn("Network offering :" + networkOfferingName + "is not enabled.");
            return false;
        }

        List<String> services = _ntwkOfferingServiceMapDao.listServicesForNetworkOffering(networkOffering.getId());
        if (services == null || services.isEmpty() || !services.contains("SourceNat")) {
            s_logger.warn("Network offering :" + networkOfferingName + " does not have necessary services to provision container cluster");
            return false;
        }

        if (networkOffering.getEgressDefaultPolicy() == false) {
            s_logger.warn("Network offering :" + networkOfferingName + "has egress default policy turned off should be on to provision container cluster.");
            return false;
        }

        long physicalNetworkId = _networkModel.findPhysicalNetworkId(zone.getId(), networkOffering.getTags(), networkOffering.getTrafficType());
        PhysicalNetwork physicalNetwork = _physicalNetworkDao.findById(physicalNetworkId);
        if (physicalNetwork == null) {
            s_logger.warn("Unable to find physical network with id: " + physicalNetworkId + " and tag: " + networkOffering.getTags());
            return false;
        }

        return true;
    }

    @Override
    public List<Class<?>> getCommands() {
        List<Class<?>> cmdList = new ArrayList<Class<?>>();
        cmdList.add(CreateContainerClusterCmd.class);
        cmdList.add(StartContainerClusterCmd.class);
        cmdList.add(StopContainerClusterCmd.class);
        cmdList.add(DeleteContainerClusterCmd.class);
        cmdList.add(ListContainerClusterCmd.class);
        return cmdList;
    }

    // Garbage collector periodically run through the container clusters marked for GC. For each container cluster
    // marked for GC, attempt is made to destroy cluster.
    public class ContainerClusterGarbageCollector extends ManagedContextRunnable {
        @Override
        protected void runInContext() {
            GlobalLock gcLock = GlobalLock.getInternLock("ContainerCluster.GC.Lock");
            try {
                if (gcLock.lock(3)) {
                    try {
                        reallyRun();
                    } finally {
                        gcLock.unlock();
                    }
                }
            } finally {
                gcLock.releaseRef();
            }
        }

        public void reallyRun() {
            try {
                List<ContainerClusterVO> containerClusters = _containerClusterDao.findContainerClustersToGarbageCollect();
                for (ContainerCluster containerCluster:containerClusters ) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Running container cluster garbage collector on container cluster name:" + containerCluster.getName());
                    }
                    try {
                        if (cleanupContainerClusterResources(containerCluster.getId())) {
                            if (s_logger.isDebugEnabled()) {
                                s_logger.debug("Container cluster: " + containerCluster.getName() + " is successfully garbage collected");
                            }
                        } else {
                            if (s_logger.isDebugEnabled()) {
                                s_logger.debug("Container cluster: " + containerCluster.getName() + " failed to get" +
                                        " garbage collected. Will be attempted to garbage collected in next run");
                            }
                        }
                    } catch (RuntimeException e) {
                        s_logger.debug("Faied to destroy container cluster name:" + containerCluster.getName() + " during GC due to " + e);
                        // proceed furhter with rest of the container cluster garbage collection
                    } catch (Exception e) {
                        s_logger.debug("Faied to destroy container cluster name:" + containerCluster.getName() + " during GC due to " + e);
                        // proceed furhter with rest of the container cluster garbage collection
                    }
                }
            } catch (Exception e) {
                s_logger.warn("Caught exception while running container cluster gc: ", e);
            }
        }
    }

    /* Container cluster scanner checks if the container cluster is in desired state. If it detects container cluster
       is not in desired state, it will trigger an event and marks the container cluster to be 'Alert' state. For e.g a
       container cluster in 'Running' state should mean all the cluster of node VM's in the custer should be running and
       number of the node VM's should be of cluster size, and the master node VM's is running. It is possible due to
       out of band changes by user or hosts going down, we may end up one or more VM's in stopped state. in which case
       scanner detects these changes and marks the cluster in 'Alert' state. Similarly cluster in 'Stopped' state means
       all the cluster VM's are in stopped state any mismatch in states should get picked up by container cluster and
       mark the container cluster to be 'Alert' state. Through recovery API, or reconciliation clusters in 'Alert' will
       be brought back to known good state or desired state.
     */
    public class ContainerClusterStatusScanner extends ManagedContextRunnable {
        @Override
        protected void runInContext() {
            GlobalLock gcLock = GlobalLock.getInternLock("ContainerCluster.State.Scanner.Lock");
            try {
                if (gcLock.lock(3)) {
                    try {
                        reallyRun();
                    } finally {
                        gcLock.unlock();
                    }
                }
            } finally {
                gcLock.releaseRef();
            }
        }

        public void reallyRun() {
            try {

                // run through container clusters in 'Running' state and ensure all the VM's are Running in the cluster
                List<ContainerClusterVO> runningContainerClusters = _containerClusterDao.findContainerClustersInState(ContainerCluster.State.Running);
                for (ContainerCluster containerCluster : runningContainerClusters ) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Running container cluster state scanner on container cluster name:" + containerCluster.getName());
                    }
                    try {
                        if (!isClusterInDesiredState(containerCluster, VirtualMachine.State.Running)) {
                            stateTransitTo(containerCluster.getId(), ContainerCluster.Event.FaultsDetected);
                        }
                    } catch (Exception e) {
                        s_logger.warn("Failed to run through VM states of container cluster due to " + e);
                    }
                }

                // run through container clusters in 'Stopped' state and ensure all the VM's are Stopped in the cluster
                List<ContainerClusterVO> stoppedContainerClusters = _containerClusterDao.findContainerClustersInState(ContainerCluster.State.Stopped);
                for (ContainerCluster containerCluster : stoppedContainerClusters ) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Running container cluster state scanner on container cluster name:" + containerCluster.getName());
                    }
                    try {
                        if (!isClusterInDesiredState(containerCluster, VirtualMachine.State.Stopped)) {
                            stateTransitTo(containerCluster.getId(), ContainerCluster.Event.FaultsDetected);
                        }
                    } catch (Exception e) {
                        s_logger.warn("Failed to run through VM states of container cluster due to " + e);
                    }
                }

                // run through container clusters in 'Alert' state and reconcile state as 'Running' if the VM's are running
                List<ContainerClusterVO> alertContainerClusters = _containerClusterDao.findContainerClustersInState(ContainerCluster.State.Alert);
                for (ContainerCluster containerCluster : alertContainerClusters ) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Running container cluster state scanner on container cluster name:" + containerCluster.getName());
                    }
                    try {
                        if (isClusterInDesiredState(containerCluster, VirtualMachine.State.Running)) {
                            // mark the cluster to be running
                            stateTransitTo(containerCluster.getId(), ContainerCluster.Event.RecoveryRequested);
                            stateTransitTo(containerCluster.getId(), ContainerCluster.Event.OperationSucceeded);
                        }
                    } catch (Exception e) {
                        s_logger.warn("Failed to run through VM states of container cluster status scanner due to " + e);
                    }
                }

            } catch (RuntimeException e) {
                s_logger.warn("Caught exception while running container cluster state scanner.", e);
            } catch (Exception e) {
                s_logger.warn("Caught exception while running container cluster state scanner.", e);
            }
        }
    }

    // checks if container cluster is in desired state
    boolean isClusterInDesiredState(ContainerCluster containerCluster, VirtualMachine.State state) {
        List<ContainerClusterVmMapVO> clusterVMs = _containerClusterVmMapDao.listByClusterId(containerCluster.getId());

        // check if all the VM's are in same state
        for (ContainerClusterVmMapVO clusterVm : clusterVMs) {
            VMInstanceVO vm = _vmInstanceDao.findByIdIncludingRemoved(clusterVm.getVmId());
            if (vm.getState() != state) {
                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("Found VM in the container cluster: " + containerCluster.getName() +
                            " in state: " + vm.getState().toString() + " while expected to be in state: " + state.toString() +
                            " So moving the cluster to Alert state for reconciliation.");
                }
                return false;
            }
        }

        // check cluster is running at desired capacity include master node as well, so count should be cluster size + 1
        if (clusterVMs.size() != (containerCluster.getNodeCount() + 1)) {
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Found only " + clusterVMs.size() + " VM's in the container cluster: " + containerCluster.getName() +
                        " in state: " + state.toString() + " While expected number of VM's to " +
                        " be in state: " + state.toString() + " is " + (containerCluster.getNodeCount() + 1) +
                        " So moving the cluster to Alert state for reconciliation.");
            }
            return false;
        }
        return true;
    }

    @Override
    public boolean start() {
        _gcExecutor.scheduleWithFixedDelay(new ContainerClusterGarbageCollector(), 300, 300, TimeUnit.SECONDS);
        _stateScanner.scheduleWithFixedDelay(new ContainerClusterStatusScanner(), 300, 30, TimeUnit.SECONDS);
        return true;
    }

    @Override
    public boolean configure(String name, Map<String, Object> params) throws ConfigurationException {
        _name = name;
        _configParams = params;
        _gcExecutor = Executors.newScheduledThreadPool(1, new NamedThreadFactory("Container-Cluster-Scavenger"));
        _stateScanner = Executors.newScheduledThreadPool(1, new NamedThreadFactory("Container-Cluster-State-Scanner"));
        return true;
    }
}
