CREATE TABLE `cloud`.`container_cluster` (
    `id` bigint unsigned NOT NULL auto_increment COMMENT 'id',
    `uuid` varchar(40),
    `name` varchar(255) NOT NULL,
    `description` varchar(4096) NULL COMMENT 'description',
    `zone_id` bigint unsigned NOT NULL COMMENT 'zone id',
    `service_offering_id` bigint unsigned COMMENT 'service offering id for the cluster VM',
    `template_id` bigint unsigned COMMENT 'vm_template.id',
    `network_id` bigint unsigned COMMENT 'network this public ip address is associated with',
    `node_count` bigint NOT NULL default '0',
    `account_id` bigint unsigned NOT NULL COMMENT 'owner of this cluster',
    `domain_id` bigint unsigned NOT NULL COMMENT 'owner of this cluster',
    `state` char(32) NOT NULL COMMENT 'current state of this cluster',
    `key_pair` varchar(40),
    `cores` bigint unsigned NOT NULL COMMENT 'number of cores',
    `memory` bigint unsigned NOT NULL COMMENT 'total memory',
    `endpoint` varchar(255) COMMENT 'url endpoint of the container cluster manager api access',
    `console_endpoint` varchar(255) COMMENT 'url for the container cluster manager dashbaord',

    CONSTRAINT `fk_cluster__zone_id` FOREIGN KEY `fk_cluster__zone_id` (`zone_id`) REFERENCES `data_center` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_cluster__service_offering_id` FOREIGN KEY `fk_cluster__service_offering_id` (`service_offering_id`) REFERENCES `service_offering`(`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_cluster__template_id` FOREIGN KEY `fk_cluster__template_id`(`template_id`) REFERENCES `vm_template`(`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_cluster__network_id` FOREIGN KEY `fk_cluster__network_id`(`network_id`) REFERENCES `networks`(`id`) ON DELETE CASCADE,

    PRIMARY KEY(`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT IGNORE INTO `cloud`.`configuration` VALUES ('Advanced', 'DEFAULT', 'management-server',
'cloud.container.cluster.template.name', null, 'template name', '-1', NULL, NULL, 0);

INSERT IGNORE INTO `cloud`.`configuration` VALUES ('Advanced', 'DEFAULT', 'management-server',
'cloud.container.cluster.master.cloudconfig', '/etc/cloudstack/management/k8s-master.yml' , 'file location path of the cloud config used for creating container cluster master node', '/etc/cloudstack/management/k8s-master.yml', NULL , NULL, 0);

INSERT IGNORE INTO `cloud`.`configuration` VALUES ('Advanced', 'DEFAULT', 'management-server',
'cloud.container.cluster.node.cloudconfig', '/etc/cloudstack/management/k8s-node.yml', 'file location path of the cloud config used for creating container cluster node', '/etc/cloudstack/management/k8s-node.yml', NULL , NULL, 0);

CREATE TABLE `cloud`.`container_cluster_vm_map` (
    `id` bigint unsigned NOT NULL auto_increment COMMENT 'id',
    `cluster_id` bigint unsigned NOT NULL COMMENT 'cluster id',
    `vm_id` bigint unsigned NOT NULL COMMENT 'vm id',

    PRIMARY KEY(`id`),
    CONSTRAINT `container_cluster_vm_map_cluster__id` FOREIGN KEY `container_cluster_vm_map_cluster__id`(`cluster_id`) REFERENCES `container_cluster`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `cloud`.`container_cluster_details` (
    `id` bigint unsigned NOT NULL auto_increment COMMENT 'id',
    `cluster_id` bigint unsigned NOT NULL COMMENT 'cluster id',
    `username` varchar(255) NOT NULL,
    `password` varchar(255) NOT NULL,

    PRIMARY KEY(`id`),
    CONSTRAINT `container_cluster_details_cluster__id` FOREIGN KEY `container_cluster_details_cluster__id`(`cluster_id`) REFERENCES `container_cluster`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
