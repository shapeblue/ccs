%define __os_install_post %{nil}
%global debug_package %{nil}

# DISABLE the post-percentinstall java repacking and line number stripping
# we need to find a way to just disable the java repacking and line number stripping, but not the autodeps

Name:      cloudstack
Summary:   CloudStack Container Service Plugin
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
License:   ShapeBlue License
Vendor:    ShapeBlue Engineering <engineering@shapeblue.com>
Packager:  ShapeBlue Engineering <engineering@shapeblue.com>
Group:     System Environment/Libraries
Source0:   %{name}-%{_maventag}.tgz
BuildRoot: %{_tmppath}/%{name}-%{_maventag}-%{release}-build

%description
CloudStack Container Service plugin by ShapeBlue.

%package ccs
Summary:   CloudStack Container Service Plugin
Requires: %{name}-management
Group:     System Environment/Libraries
%description ccs
The CloudStack Container Service Plugin by ShapeBlue.

%prep
echo "Starting CloudStack CCS build..."

%setup -q -n %{name}-%{_maventag}

%build

echo "Executing maven packaging..."
mvn clean package

%install
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/%{name}-management/webapps/client/WEB-INF/lib
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/%{name}-management/webapps/client/plugins
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/%{name}-management/setup
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/%{name}/management

cp -r target/cloud-plugin-ccs-%{_maventag}.jar ${RPM_BUILD_ROOT}%{_datadir}/%{name}-management/webapps/client/WEB-INF/lib/
cp -r ../../../../../../ui/plugins/ccs ${RPM_BUILD_ROOT}%{_datadir}/%{name}-management/webapps/client/plugins/
cp -r ../../../../schema/* ${RPM_BUILD_ROOT}%{_datadir}/%{name}-management/setup/
cp -r ../../../../conf/* ${RPM_BUILD_ROOT}%{_sysconfdir}/%{name}/management

%clean
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%preun ccs
echo "Pre-uninstall ccs pkg"

%pre ccs
echo "Pre-install ccs pkg"

%post ccs
echo "Post-install ccs pkg"
if [ "$1" == "1" ] ; then
    # Handle upgrade case here
fi

if [ -f /usr/share/cloudstack-management/webapps/client/plugins/plugins.js ]; then
    if ! grep -q ccs /usr/share/cloudstack-management/webapps/client/plugins/plugins.js; then
        echo "Enabling CloudStack Container Service UI Plugin"
        rm -f /usr/share/cloudstack-management/webapps/client/plugins/plugins.js.gz
        sed -i  "/cloudStack.plugins/a 'ccs'," /usr/share/cloudstack-management/webapps/client/plugins/plugins.js
        gzip -c /usr/share/cloudstack-management/webapps/client/plugins/plugins.js > /usr/share/cloudstack-management/webapps/client/plugins/plugins.js.gz
    fi
fi

%postun ccs
if [ "$1" == "0" ] ; then
    if [ -f /usr/share/cloudstack-management/webapps/client/plugins/plugins.js ]; then
        if grep -q ccs /usr/share/cloudstack-management/webapps/client/plugins/plugins.js; then
            echo "Disabling CloudStack Container Service UI Plugin"
            rm -f /usr/share/cloudstack-management/webapps/client/plugins/plugins.js.gz
            sed -i  "/'ccs'/d" /usr/share/cloudstack-management/webapps/client/plugins/plugins.js
            gzip -c /usr/share/cloudstack-management/webapps/client/plugins/plugins.js > /usr/share/cloudstack-management/webapps/client/plugins/plugins.js.gz
        fi
    fi
fi

%files ccs
%defattr(-,root,root,-)
%{_datadir}/%{name}-management/webapps
%{_datadir}/%{name}-management/setup/*.sql
%{_sysconfdir}/%{name}/management/*.yml

%changelog
* Fri Jun 03 2016 ShapeBlue <enginering@shapeblue.com> 1.0.0
- CloudStack Container Service Plugin
