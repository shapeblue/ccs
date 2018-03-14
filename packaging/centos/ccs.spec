%define __os_install_post %{nil}
%global debug_package %{nil}

# DISABLE the post-percentinstall java repacking and line number stripping
# we need to find a way to just disable the java repacking and line number stripping, but not the autodeps

Name:      shapeblue
Summary:   ShapeBlue CloudStack Container Service Plugin
#http://fedoraproject.org/wiki/PackageNamingGuidelines#Pre-Release_packages
%if "%{?_prerelease}" != ""
%define _maventag %{_ver}-SNAPSHOT
Release:   %{_rel}
%else
%define _maventag %{_ver}
Release:   %{_rel}
%endif

%{!?python_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

Version:   %{_ver}
License:   Apache License, Version 2
Vendor:    ShapeBlue Ltd <CCS-help@shapeblue.com>
Packager:  ShapeBlue Ltd <CCS-help@shapeblue.com>
Group:     System Environment/Libraries
Source0:   %{name}-%{_maventag}.tgz
BuildRoot: %{_tmppath}/%{name}-%{_maventag}-%{release}-build

%description
CloudStack Container Service plugin by ShapeBlue.

%package ccs
Summary:   ShapeBlue CloudStack Container Service Plugin
Requires:  cloudstack-management >= 4.5.0
Group:     System Environment/Libraries
%description ccs
The CloudStack Container Service Plugin by ShapeBlue.

%prep
echo "Starting ShapeBlue CCS build..."

%setup -q -n %{name}-%{_maventag}

%build

echo "Executing maven packaging..."
mvn clean package

%install
echo "Installing ShapeBlue Cloudstack Container Service Plugin"
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/webapp/WEBB-INF/lib
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/webapp/plugins
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/setup
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/cloudstack/management
mkdir -p ${RPM_BUILD_ROOT}%{_bindir}/

cp -r target/cloud-plugin-shapeblue-ccs-%{_maventag}.jar ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/webapp/WEBB-INF/lib/
cp -r ../../../../ui/plugins/ccs ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/webapp/plugins/
cp -r ../../../../schema/delete-schema-ccs.sql ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/setup/delete-schema-ccs.sql
cp -r ../../../../conf/* ${RPM_BUILD_ROOT}%{_sysconfdir}/cloudstack/management
cp -r ../../../../scripts/setup/* ${RPM_BUILD_ROOT}%{_bindir}/
cp ../../../../deps/kubectl ${RPM_BUILD_ROOT}%{_bindir}/
cp target/dependency/flyway-core-*.jar ${RPM_BUILD_ROOT}%{_datadir}/cloudstack-management/webapp/WEBB-INF/lib/

%clean
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%preun ccs
echo "Running through the pre-uninstall ccs pkg steps"

%pre ccs
echo "Running through pre-install ccs pkg steps"

%post ccs
echo "Running through post-install ccs pkg steps"
#if [ "$1" == "1" ] ; then
    # Handle upgrade case here
#fi

if [ -f /usr/share/cloudstack-management/webapp/plugins/plugins.js ]; then
    if ! grep -q ccs /usr/share/cloudstack-management/webapp/plugins/plugins.js; then
        echo "Enabling CloudStack Container Service UI Plugin"
        rm -f /usr/share/cloudstack-management/webapp/plugins/plugins.js.gz
        sed -i  "/cloudStack.plugins/a 'ccs'," /usr/share/cloudstack-management/webapp/plugins/plugins.js
        gzip -c /usr/share/cloudstack-management/webapp/plugins/plugins.js > /usr/share/cloudstack-management/webapp/plugins/plugins.js.gz
        echo "CloudStack Container Service UI Plugin successfully enabled"
    fi
fi

%postun ccs
echo "Running through the post-uninstall ccs pkg steps"
if [ "$1" == "0" ] ; then
    if [ -f /usr/share/cloudstack-management/webapp/plugins/plugins.js ]; then
        if grep -q ccs /usr/share/cloudstack-management/webapp/plugins/plugins.js; then
            echo "Disabling CloudStack Container Service UI Plugin"
            rm -f /usr/share/cloudstack-management/webapp/plugins/plugins.js.gz
            sed -i  "/'ccs'/d" /usr/share/cloudstack-management/webapp/plugins/plugins.js
            gzip -c /usr/share/cloudstack-management/webapp/plugins/plugins.js > /usr/share/cloudstack-management/webapp/plugins/plugins.js.gz
        fi
    fi
fi

%files ccs
%defattr(-,root,root,-)
%{_datadir}/cloudstack-management/webapps
%{_datadir}/cloudstack-management/setup/delete-schema-ccs.sql
%{_sysconfdir}/cloudstack/management/*.yml
%{_bindir}/ccs-cleanup-database
%{_bindir}/ccs-template-install
%{_bindir}/kubectl
%changelog
* Mon Jul 11 2016 Shape Blue Ltd <CCS-help@shapeblue.com> 1.0.0
- CloudStack Container Service Plugin
