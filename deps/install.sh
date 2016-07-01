
version="4.5.2"
for dep in checkstyle cloud-api cloud-utils cloud-server cloud-core cloud-engine-components-api cloud-engine-orchestration cloud-engine-api cloud-engine-schema cloud-framework-config cloud-framework-db cloud-framework-managed-context cloud-framework-security; do
    echo "Installing $dep"
    mvn -q install:install-file -Dfile=$dep-$version.jar -DgroupId=org.apache.cloudstack -DartifactId=$dep   -Dversion=$version   -Dpackaging=jar
done
