# Copyright 2016 ShapeBlue Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/bin/bash

version="4.11.0.0"
for dep in checkstyle cloud-api cloud-utils cloud-server cloud-core cloud-engine-components-api cloud-engine-orchestration cloud-engine-api cloud-engine-schema cloud-framework-config cloud-framework-db cloud-framework-managed-context cloud-framework-security; do
    echo "Installing $dep"
    mvn -q install:install-file -Dfile=$dep-$version.jar -DgroupId=org.apache.cloudstack -DartifactId=$dep   -Dversion=$version   -Dpackaging=jar
done
