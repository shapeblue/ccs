-- Copyright (C) 2016 ShapeBlue Ltd and its licensors.
-- All Rights Reserved. The following is Source Code and is subject to all
-- restrictions on such code as contained in the End User License Agreement
-- accompanying this product.

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
