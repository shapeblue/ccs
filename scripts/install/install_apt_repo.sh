#!/bin/bash
# Copyright (C) 2016 ShapeBlue Ltd and its licensors.
# All Rights Reserved. The following is Source Code and is subject to all
# restrictions on such code as contained in the End User License Agreement
# accompanying this product.

unknown_os ()
{
  echo "Unfortunately, your operating system distribution and version are not supported by this script."
  echo
  echo "You can override the OS detection by setting os= and dist= prior to running this script."
  echo "You can find a list of supported OSes and distributions on our website: https://packagecloud.io/docs#os_distro_version"
  echo
  echo "For example, to force Ubuntu Trusty: os=ubuntu dist=trusty ./script.sh"
  echo
  echo "Please email support@packagecloud.io and let us know if you run into any issues."
  exit 1
}

eula_acceptance ()
{

  printf "End user License Agreement (EULA) for CloudStack Container Service

  The EULA for this software can be found at
  http://shapeblue.com/ccs-eula/

  Please download and read this EULA carefully, as it sets out the basis upon which we license the Software for use.
  BY INSTALLING THE SOFTWARE, YOU ARE AGREEING TO BE BOUND BY THE TERMS OF THIS EULA.\n\n"

  echo -n "Answer yes if you have downloaded and agree to be bound by the terms of the EULA for CloudStack Container Service? [yes/no] "
  read license_response

  normalized_license_response=`echo "$license_response" | awk '{print tolower($0)}'`
  if [[ $normalized_license_response != "yes" ]]; then
    echo "The CloudStack Container Service cannot be installed unless the EULA has been accepted."
    exit 1
  fi

}

curl_check ()
{
  echo "Checking for curl..."
  if command -v curl > /dev/null; then
    echo "Detected curl..."
  else
    echo "Installing curl..."
    apt-get install -q -y curl
  fi
}

install_debian_keyring ()
{
  if [ "${os}" = "debian" ]; then
    echo "Installing debian-archive-keyring which is needed for installing "
    echo "apt-transport-https on many Debian systems."
    apt-get install -y debian-archive-keyring &> /dev/null
  fi
}

get_unique_id ()
{
  echo "A unique ID was not specified, using the machine's hostname..."

  unique_id=`hostname -f 2>/dev/null`
  if [ "$unique_id" = "" ]; then
    unique_id=`hostname 2>/dev/null`
    if [ "$unique_id" = "" ]; then
      unique_id=$HOSTNAME
    fi
  fi

  if [ "$unique_id" = "" -o "$unique_id" = "(none)" ]; then
    echo "This script tries to use your machine's hostname as a unique ID by"
    echo "default, however, this script was not able to determine your "
    echo "hostname!"
    echo
    echo "You can override this by setting 'unique_id' to any unique "
    echo "identifier (hostname, shasum of hostname, "
    echo "etc) prior to running this script."
    echo
    echo
    echo "If you'd like to use your hostname, please consult the documentation "
    echo "for your system. The files you need to modify to do this vary "
    echo "between Linux distribution and version."
    echo
    echo
    exit 1
  fi
}

detect_os ()
{
  if [[ ( -z "${os}" ) && ( -z "${dist}" ) ]]; then
    # some systems dont have lsb-release yet have the lsb_release binary and
    # vice-versa
    if [ -e /etc/lsb-release ]; then
      . /etc/lsb-release

      if [ "${ID}" = "raspbian" ]; then
        os=${ID}
        dist=`cut --delimiter='.' -f1 /etc/debian_version`
      else
        os=${DISTRIB_ID}
        dist=${DISTRIB_CODENAME}

        if [ -z "$dist" ]; then
          dist=${DISTRIB_RELEASE}
        fi
      fi

    elif [ `which lsb_release 2>/dev/null` ]; then
      dist=`lsb_release -c | cut -f2`
      os=`lsb_release -i | cut -f2 | awk '{ print tolower($1) }'`

    elif [ -e /etc/debian_version ]; then
      # some Debians have jessie/sid in their /etc/debian_version
      # while others have '6.0.7'
      os=`cat /etc/issue | head -1 | awk '{ print tolower($1) }'`
      if grep -q '/' /etc/debian_version; then
        dist=`cut --delimiter='/' -f1 /etc/debian_version`
      else
        dist=`cut --delimiter='.' -f1 /etc/debian_version`
      fi

    else
      unknown_os
    fi
  fi

  if [ -z "$dist" ]; then
    unknown_os
  fi

  # remove whitespace from OS and dist name
  os="${os// /}"
  dist="${dist// /}"

  echo "Detected operating system as $os/$dist."
}

main ()
{
  eula_acceptance
  detect_os
  curl_check

  # Need to first run apt-get update so that apt-transport-https can be
  # installed
  echo -n "Running apt-get update... "
  apt-get update &> /dev/null
  echo "done."

  # Install the debian-archive-keyring package on debian systems so that
  # apt-transport-https can be installed next
  install_debian_keyring

  echo -n "Installing apt-transport-https... "
  apt-get install -y apt-transport-https &> /dev/null
  echo "done."

  if [ -z "$unique_id" ]; then
    get_unique_id
  fi

  echo "Found unique id: ${unique_id}"
  gpg_key_install_url="https://${master_token}:@packagecloud.io/install/repositories/shapeblue/ccs/gpg_key_url.list?os=${os}&dist=${dist}&name=${unique_id}"
  apt_config_url="https://${master_token}:@packagecloud.io/install/repositories/shapeblue/ccs/config_file.list?os=${os}&dist=${dist}&name=${unique_id}&source=script"

  gpg_key_url=`curl -L "${gpg_key_install_url}"`
  if [ "${gpg_key_url}" = "" ]; then
    echo "Unable to retrieve GPG key URL from: ${gpg_key_url}."
    echo "Please contact support@packagecloud.io"
    exit 1
  fi


  apt_source_path="/etc/apt/sources.list.d/shapeblue_ccs.list"

  echo -n "Installing $apt_source_path..."

  # create an apt config file for this repository
  curl -sSf "${apt_config_url}" > $apt_source_path
  curl_exit_code=$?

  if [ "$curl_exit_code" = "22" ]; then
    echo
    echo
    echo -n "Unable to download repo config from: "
    echo "${apt_config_url}"
    echo
    echo "This usually happens if your operating system is not supported by "
    echo "packagecloud.io, or this script's OS detection failed."
    echo
    echo "You can override the OS detection by setting os= and dist= prior to running this script."
    echo "You can find a list of supported OSes and distributions on our website: https://packagecloud.io/docs#os_distro_version"
    echo
    echo "For example, to force Ubuntu Trusty: os=ubuntu dist=trusty ./script.sh"
    echo
    echo "If you are running a supported OS, please email support@packagecloud.io and report this."
    [ -e $apt_source_path ] && rm $apt_source_path
    exit 1
  elif [ "$curl_exit_code" = "35" ]; then
    echo "curl is unable to connect to packagecloud.io over TLS when running: "
    echo "    curl ${apt_config_url}"
    echo "This is usually due to one of two things:"
    echo
    echo " 1.) Missing CA root certificates (make sure the ca-certificates package is installed)"
    echo " 2.) An old version of libssl. Try upgrading libssl on your system to a more recent version"
    echo
    echo "Contact support@packagecloud.io with information about your system for help."
    [ -e $apt_source_path ] && rm $apt_source_path
    exit 1
  elif [ "$curl_exit_code" -gt "0" ]; then
    echo
    echo "Unable to run: "
    echo "    curl ${apt_config_url}"
    echo
    echo "Double check your curl installation and try again."
    [ -e $apt_source_path ] && rm $apt_source_path
    exit 1
  else
    echo "done."
  fi

  echo -n "Importing packagecloud gpg key... "
  # import the gpg key
  curl -L "${gpg_key_url}" 2> /dev/null | apt-key add - &>/dev/null
  echo "done."

  echo -n "Running apt-get update... "
  # update apt on this system
  apt-get update &> /dev/null
  echo "done."

  echo
  echo "The repository is setup! You can now install packages."
}

master_token=$1
if [[ ! $1 ]]; then
  echo -n "Token: "
  read master_token
fi

if [[ ! $master_token ]]; then
  echo "A token must be specified.  Usage: $0 <token>"
  exit 1
fi

main
