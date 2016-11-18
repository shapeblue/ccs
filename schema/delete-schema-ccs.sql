-- Copyright 2016 ShapeBlue Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

use cloud;

DROP TABLE IF EXISTS `cloud`.`sb_ccs_container_cluster_vm_map`;
DROP TABLE IF EXISTS `cloud`.`sb_ccs_container_cluster_details`;
DROP TABLE IF EXISTS `cloud`.`sb_ccs_container_cluster`;
DROP TABLE IF EXISTS `cloud`.`sb_ccs_schema_version`;

DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.template.name';
DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.master.cloudconfig';
DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.node.cloudconfig';
DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.network.offering';

SET @ccs_ntwk_offering_id = (select id from network_offerings where name='DefaultNetworkOfferingforContainerService' and removed IS NULL);

UPDATE `cloud`.`network_offerings` SET removed=now() where id=@ccs_ntwk_offering_id;
