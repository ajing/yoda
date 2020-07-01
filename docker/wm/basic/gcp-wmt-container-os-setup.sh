#!/bin/bash -eux

# Set Global Vars
PATH="${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin"
ZONE=$(basename "$(curl -k -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/zone')")
REGION=$(echo "$ZONE" | awk -F'-' '{ print $1"-"$2 }')
HOST_DOMAIN="${REGION}.us.walmart.net"

# Set Resolver String
if [[ "$REGION" == 'us-central1' ]];
then
  RESOLVERS='10.74.33.28, 10.74.33.34, 10.74.34.20'
elif [[ "$REGION" == 'us-east4' ]];
then
  RESOLVERS='10.74.34.20, 10.74.34.57, 10.74.33.28'
elif [[ "$REGION" == 'us-west1' ]];
then
  RESOLVERS='10.74.40.24, 10.74.40.25, 10.74.33.28'
else
  RESOLVERS='10.74.33.28, 10.74.34.20, 10.74.40.24'
fi


function set_resolverd {

  if [[ ! $( grep "${RESOLVERS//,}" /etc/systemd/resolved.conf) ]];
  then
    cat <<EOF > /etc/systemd/resolved.conf
# This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See resolved.conf(5) for details

[Resolve]
DNS=${RESOLVERS//,}
Domains=walmart.com wal-mart.com ${HOST_DOMAIN} homeoffice.wal-mart.com
#FallbackDNS=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#Cache=yes
#DNSStubListener=yes
EOF

    # Cycle Network Service
    systemctl restart systemd-resolved
  fi
}

# Main Program
function main {
  # Write proxy config to /etc/profile
  {
    echo "export http_proxy='sysproxy.wal-mart.com:8080'"
    echo "export https_proxy='sysproxy.wal-mart.com:8080'"
    echo "export no_proxy='.walmart.com,.wal-mart.com,.walmart.net,.google.internal,127.0.0.1,localhost'"
  } >> /etc/profile
  # Set ResolverD COnfig
  set_resolverd
}

# Program Invocation
main
