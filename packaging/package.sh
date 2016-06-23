#!/bin/bash

function package_deb() {
    dpkg-buildpackage -uc -us
}

function package_rpm() {
    CWD=`pwd`
    RPMDIR=$CWD/../dist/rpmbuild
    PACK_PROJECT=cloudstack

    VERSION=`(cd ../; mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=project.version) | grep --color=none '^[0-9]\.'`
    if echo $VERSION | grep -q SNAPSHOT ; then
        REALVER=`echo $VERSION | cut -d '-' -f 1`
        DEFVER="-D_ver $REALVER"
        DEFPRE="-D_prerelease 1"
        DEFREL="-D_rel SNAPSHOT"
    else
        REALVER=`echo $VERSION`
        DEFVER="-D_ver $REALVER"
        DEFREL="-D_rel 1"
    fi

    echo Preparing to package ShapeBlue CloudStack CCS ${VERSION}

    mkdir -p $RPMDIR/SPECS
    mkdir -p $RPMDIR/BUILD
    mkdir -p $RPMDIR/RPMS
    mkdir -p $RPMDIR/SRPMS
    mkdir -p $RPMDIR/SOURCES/$PACK_PROJECT-$VERSION

    echo ". preparing source tarball"
    (cd ../; tar -c --exclude .git --exclude dist  .  | tar -C $RPMDIR/SOURCES/$PACK_PROJECT-$VERSION -x )
    (cd $RPMDIR/SOURCES/; tar -czf $PACK_PROJECT-$VERSION.tgz $PACK_PROJECT-$VERSION)

    echo ". executing rpmbuild"
    cp centos/ccs.spec $RPMDIR/SPECS

    (cd $RPMDIR; rpmbuild --define "_topdir $RPMDIR" "${DEFVER}" "${DEFREL}" ${DEFPRE+"${DEFPRE}"} -bb SPECS/ccs.spec)

    if [ $? -ne 0 ]; then
        echo "RPM Build Failed "
        exit 1
    else
        echo "RPM Build Done"
    fi
    exit
}

ROOT=$PWD
cd $ROOT/../deps && bash -x install.sh && cd $ROOT

case "$1" in
  deb ) package_deb
      ;;
  rpm ) package_rpm
      ;;
  * )   package_deb
        package_rpm
      ;;
esac
