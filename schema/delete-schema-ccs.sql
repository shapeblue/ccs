use cloud;

DROP TABLE IF EXISTS `cloud`.`sb_ccs_container_cluster_vm_map`;
DROP TABLE IF EXISTS `cloud`.`sb_ccs_container_cluster_details`;
DROP TABLE IF EXISTS `cloud`.`sb_ccs_container_cluster`;
DROP TABLE IF EXISTS `cloud`.`sb_ccs_version`;

DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.template.name';
DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.master.cloudconfig';
DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.node.cloudconfig';
DELETE FROM `cloud`.`configuration` WHERE name='cloud.container.cluster.network.offering';

DELETE FROM `cloud`.`network_offerings` WHERE name='DefaultNetworkOfferingforContainerService';

SET @ccsntwk = (select id from network_offerings where name='DefaultNetworkOfferingforContainerService');

DELETE FROM `cloud`.`ntwk_offering_service_map` where  network_offering_id=@ccsntwk;
