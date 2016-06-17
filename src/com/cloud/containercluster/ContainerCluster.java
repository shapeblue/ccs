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

import org.apache.cloudstack.acl.ControlledEntity;
import org.apache.cloudstack.api.Displayable;
import org.apache.cloudstack.api.Identity;
import org.apache.cloudstack.api.InternalIdentity;
import com.cloud.utils.fsm.StateObject;
import com.cloud.utils.fsm.StateMachine2;

/**
 * ContainerCluster describes the properties of container cluster
 *
 */
public interface ContainerCluster extends ControlledEntity, com.cloud.utils.fsm.StateObject<ContainerCluster.State>, Identity, InternalIdentity, Displayable {

    enum Event {
        StartContainerCluster,
        StopContainerCluster,
        DeleteContainerCluster,
        RecoverContainerCluster,
        ScaleUpContainerCluster,
        ScaleDownContainerCluster,
        OperationSucceeded,
        OperationFailed,
        FaultyContainerCluster;
    }

    enum State {
        Created("Initial State of container cluster. At this state its just a logica/DB entry no resources concumed"),
        Starting("Resources needed for container cluster are being provisioned"),
        Running("Resources provisioned, cluster is in operational ready state to launch containers"),
        Stopping("Ephermal resources for the container cluster are being destroyed"),
        Stopped("All ephermal resources for the container cluster are destroyed, Container cluster may still have ephermal resource like persistent volumens provisioned"),
        Scaling("Transient state in which resoures are either getting scaled up/down"),
        Alert("State to represent container clusters which are not in expected desired state (operationally in active control place, stopped cluster VM's etc)."),
        Recovering("State in which container cluster is recovering from alert state"),
        Destroyed("End state of container cluster in which all resources are destroyed, cluster will not be useable further"),
        Expunge("State in which resources for the container cluster is yet to be cleaned up by garbage collector"),
        Expunging("State in whcich resource are being destroyed");

        protected static final StateMachine2<State, ContainerCluster.Event, ContainerCluster> s_fsm = new StateMachine2<State, ContainerCluster.Event, ContainerCluster>();

        public static StateMachine2<State, ContainerCluster.Event, ContainerCluster> getStateMachine() { return s_fsm; }

        static {
            s_fsm.addTransition(State.Created, Event.StartContainerCluster, State.Starting);

            s_fsm.addTransition(State.Starting, Event.OperationSucceeded, State.Running);
            s_fsm.addTransition(State.Starting, Event.OperationFailed, State.Alert);

            s_fsm.addTransition(State.Running, Event.StopContainerCluster, State.Stopping);
            s_fsm.addTransition(State.Stopping, Event.OperationSucceeded, State.Stopped);
            s_fsm.addTransition(State.Stopping, Event.OperationFailed, State.Alert);

            s_fsm.addTransition(State.Stopped, Event.StartContainerCluster, State.Starting);

            s_fsm.addTransition(State.Stopped, Event.DeleteContainerCluster, State.Expunging);
            s_fsm.addTransition(State.Expunging, Event.OperationSucceeded, State.Destroyed);
            s_fsm.addTransition(State.Expunging, Event.OperationFailed, State.Expunge);
            s_fsm.addTransition(State.Expunge, Event.DeleteContainerCluster, State.Expunging);

            s_fsm.addTransition(State.Running, Event.ScaleUpContainerCluster, State.Scaling);
            s_fsm.addTransition(State.Running, Event.ScaleDownContainerCluster, State.Scaling);
            s_fsm.addTransition(State.Scaling, Event.OperationSucceeded, State.Running);
            s_fsm.addTransition(State.Scaling, Event.OperationFailed, State.Alert);

            s_fsm.addTransition(State.Running, Event.FaultyContainerCluster, State.Alert);

            s_fsm.addTransition(State.Alert, Event.RecoverContainerCluster, State.Recovering);
            s_fsm.addTransition(State.Recovering, Event.OperationSucceeded, State.Running);
            s_fsm.addTransition(State.Recovering, Event.OperationFailed, State.Alert);

            s_fsm.addTransition(State.Alert, Event.DeleteContainerCluster, State.Expunging);
        }
        String _description;

        private State(String description) {
             _description = description;
        }
    }

    long getId();
    String getName();
    String getDescription();
    long getZoneId();
    long getServiceOfferingId();
    long getTemplateId();
    long getNetworkId();
    long getDomainId();
    long getAccountId();
    long getNodeCount();
    String getKeyPair();
    long getCores();
    long getMemory();
    String getEndpoint();
    String getConsoleEndpoint();
    @Override
    State getState();
}
