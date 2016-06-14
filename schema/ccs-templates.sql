use cloud;

INSERT INTO `cloud`.`vm_template` (uuid, unique_name, name, public, featured, created, state, type, hvm, bits, account_id, url, enable_password, display_text, format, guest_os_id, cross_zones, hypervisor_type, extractable)  VALUES (UUID(), 'CCS Template KVM', 'CCS Template KVM', 1, 1, now(), 'Active', 'BUILTIN', 0, 64, 1, 'http://dl.openvm.eu/cloudstack/coreos/x86_64/coreos_production_cloudstack_image-kvm.qcow2.bz2',  0, 'Cloudstack Container Service Template (KVM)', 'QCOW2', 99, 1, 'KVM',1);

