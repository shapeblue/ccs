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

INSERT INTO `cloud`.`vm_template` (uuid, unique_name, name, public, featured, created, state, type, hvm, bits, account_id, url, enable_password, display_text, format, guest_os_id, cross_zones, hypervisor_type, extractable)  VALUES (UUID(), 'CCS Template KVM', 'CCS Template KVM', 1, 1, now(), 'Active', 'BUILTIN', 0, 64, 1, 'http:--dl.openvm.eu/cloudstack/coreos/x86_64/coreos_production_cloudstack_image-kvm.qcow2.bz2',  0, 'Cloudstack Container Service Template (KVM)', 'QCOW2', 99, 1, 'KVM',1);

