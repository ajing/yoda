#!/bin/bash -eux

# Set Global Vars
PATH="${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin"
PROXY='http://sysproxy.wal-mart.com:8080'
IP_ADDR=$(curl -k -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip')
ZONE=$(basename "$(curl -k -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/zone')")
IMAGE=$(basename "$(curl -k -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/image')")
REGION=$(echo "$ZONE" | awk -F'-' '{ print $1"-"$2 }')
SHORT_HOSTNAME=$(hostname -s)
HOST_DOMAIN="${REGION}.us.walmart.net"
FQDN="${SHORT_HOSTNAME}.${HOST_DOMAIN}"
DNS_SCRIPT_PATH='/etc/init.d/gcp_dns_update.sh'
LOGGING_SCRIPT_NAME="install-logging-agent.sh"
INSTALL_SCRIPT_PATH="/root/${LOGGING_SCRIPT_NAME}"
AUDITD_CONF_FILE='/etc/audit/auditd.conf'
AUDITD_RULES_FILE='/etc/audit/audit.rules'
URL_PATH="https://dl.google.com/cloudagents"


# Set Resolver String
if [[ "$REGION" == 'us-central1' ]];
then
  RESOLVERS=('10.74.33.28' '10.74.33.34')
  FALLBACK_DNS='10.74.34.20'
elif [[ "$REGION" == 'us-east4' ]];
then
  RESOLVERS=('10.74.34.20' '10.74.34.57')
  FALLBACK_DNS='10.74.33.28'
elif [[ "$REGION" == 'us-west1' ]];
then
  RESOLVERS=('10.74.40.24' '10.74.40.25')
  FALLBACK_DNS='10.74.33.28'
else
  RESOLVERS=('10.74.33.28' '10.74.34.20')
  FALLBACK_DNS='10.74.40.24'
fi

function set_hostname {
  # Set Hostname if not already matching proper FQDN
  # Install dbus if apt to ensure hostnamectl command
  apt="$1"
  if [[ "$apt" == "apt" ]];
  then
    if [[ ! $(dpkg -l dbus) ]];
    then
      apt -y install dbus
    fi
  fi

  # Set hostname if needed
  if [[ ! $(hostname -f) == "${FQDN}" ]];
  then
    hostname "${FQDN}"
    systemctl enable systemd-hostnamed
    systemctl start systemd-hostnamed
    hostnamectl set-hostname "${FQDN}"
    systemctl restart systemd-hostnamed
  fi
}

function add_dhclient_options {
  # Add dhclient options for proper name resolution
  dhclient_conf_file="$1"
  network_service="$2"
  if [[ ! $(grep 'walmart.net' "$dhclient_conf_file") ]];
  then
cat <<EOF >> "$dhclient_conf_file"
supersede domain-name "$HOST_DOMAIN";
supersede domain-search "walmart.com", "wal-mart.com", "walmart.net", "homeoffice.wal-mart.com";
supersede domain-name-servers $(TMP="${RESOLVERS[@]}"; echo -n ${TMP//[[:space:]]/', '});
EOF
    if [[ ! $( grep "^${IP_ADDR}.*${FQDN}.*$" /etc/hosts) ]];
    then
      echo "${IP_ADDR} ${FQDN} ${SHORT_HOSTNAME}" >> /etc/hosts
    fi

    # Cycle Network Service
    systemctl restart "$network_service"
  fi
}

function set_resolverd {

  if [[ ! $( grep "${RESOLVERS[@]}" /etc/systemd/resolved.conf) ]];
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
DNS=${RESOLVERS[@]}
Domains=walmart.com wal-mart.com walmart.net homeoffice.wal-mart.com google.internal
FallbackDNS=${FALLBACK_DNS}
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

function set_proxy {
  package_provider="$1"
  provider_conf_file="$2"
  if [[ "$package_provider" == "rpm" ]];
  then
    # Set Yum proxy
    if [[ ! $(grep 'proxy' "$provider_conf_file") ]];
    then
      echo "proxy=${PROXY}" >> "$provider_conf_file"
    fi
  elif [[ "$package_provider" == "apt" ]];
  then
    # Set Apt Proxy
    if [[ ! $(grep 'Acquire::http::proxy' "$provider_conf_file") ]];
    then
      echo "Acquire::http::proxy \"${PROXY}\";" >> "$provider_conf_file"
      echo "Acquire::https::proxy \"${PROXY}\";" >> "$provider_conf_file"
      cat <<'DIRECTHOST' >> "$provider_conf_file"
Acquire::http::Proxy {
    repository.walmart.com DIRECT;
    repository.cache.walmart.com DIRECT;
};
Acquire::https::Proxy {
    repository.walmart.com DIRECT;
    repository.cache.walmart.com DIRECT;
};
DIRECTHOST
    fi
  fi
}

function add_ddns_script {
  dns_cmd=$1
  package_provider=$2
  package_cmd=$3
  $package_cmd
  cat <<"SCRIPT" > "$DNS_SCRIPT_PATH"
#!/bin/bash -eux

# Temporary script to keep DNS updated until GCP DHCP/DNS issues are corrected
### BEGIN INIT INFO
# Provides: gcp_dns_update.sh
# Required-Start: $network
# Required-Stop: $network
# Should-Start:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Description: Add GCP DNS records
### END INIT INFO

IP_ADDR=$(curl -k -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip')
ZONE=$(basename "$(curl -k -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/zone')")
REGION=$(echo "$ZONE" | awk -F'-' '{ print $1"-"$2 }')
SHORT_HOSTNAME=$(hostname -s)
HOST_DOMAIN="${REGION}.us.walmart.net"
FQDN="${SHORT_HOSTNAME}.${HOST_DOMAIN}"

# Get IP and split out octets for PTR record
OCT1=$(echo "$IP_ADDR" |awk -F. \{'print $1'\})
OCT2=$(echo "$IP_ADDR" |awk -F. \{'print $2'\})
OCT3=$(echo "$IP_ADDR" |awk -F. \{'print $3'\})
OCT4=$(echo "$IP_ADDR" |awk -F. \{'print $4'\})

# Added Empty line to prevent NOUPDATE Error
# Refer https://superuser.com/questions/977132/when-using-nsupdate-to-update-both-a-and-ptr-records-why-do-i-get-update-faile
if [ "$1" = "start" ]; then
  /usr/bin/nsupdate << EOF
  update delete $FQDN A

  update add $FQDN 1800 A $IP_ADDR



  update delete $OCT4.$OCT3.$OCT2.$OCT1.in-addr.arpa 1800 IN ANY

  update add $OCT4.$OCT3.$OCT2.$OCT1.in-addr.arpa. 1800 IN PTR $FQDN.

  send
EOF

  if [ $? -eq 0 ]; then
    echo 'Successfully updated DNS records..'
    echo "$FQDN" "$IP_ADDR"
  else
    echo 'DNS update failed!!!'
  fi
fi
SCRIPT
  chmod +x "$DNS_SCRIPT_PATH"
  $dns_cmd

  # Logic to determine whether or not DNS records need to be updated
  update_dns_records=true
  for resolver in $RESOLVERS
  do
    host_out=$(host "$(hostname -f)" "$resolver" || true)
    echo "$host_out";
    if [[ $? -eq 0 ]];
    then
      host_out_ip_addr=$(echo "$host_out" | awk '{ print $NF }')
      echo "Found DNS record with this IP: ${host_out_ip_addr}"
      if [[ "$host_out_ip_addr" == "$IP_ADDR" ]];
      then
        echo "DNS records already up to date"
        update_dns_records=false
      fi
      break
    fi
  done

  if [[ "$update_dns_records" == true ]];
  then
    echo "Updating DNS records..."
    $DNS_SCRIPT_PATH start
  fi
}

function add_apt_repos {
  # Check for/remove Backport Repo file
  BACKPORT_REPO='/etc/apt/sources.list.d/backports.list'
  [[ -f "$BACKPORT_REPO" ]] && rm -f "$BACKPORT_REPO"
  # Source Release Var to set as vars
  RELEASE_FILE='/etc/os-release'
  # Parse os-release to grab VERSION_CODENAME/ID Vars
  # shellcheck source=/dev/null
  [[ -f "$RELEASE_FILE" ]] && . "$RELEASE_FILE"
  if [[ "$ID" == "debian" ]];
  then
  cat <<EOF > "/etc/apt/sources.list"
deb http://repository.walmart.com/repository/debian-security/ ${VERSION_CODENAME}/updates main
deb-src http://repository.walmart.com/repository/debian-security/ ${VERSION_CODENAME}/updates main
deb http://repository.walmart.com/repository/debian-releases/ ${VERSION_CODENAME}-updates main
deb-src http://repository.walmart.com/repository/debian-releases/ ${VERSION_CODENAME}-updates main
deb http://repository.walmart.com/repository/debian-releases/ $VERSION_CODENAME main
deb-src http://repository.walmart.com/repository/debian-releases/ $VERSION_CODENAME main
EOF
elif [[ "$ID" == "ubuntu" ]];
then
  cat <<EOF > "/etc/apt/sources.list"
deb https://repository.cache.walmart.com/repository/ubuntu-archive/ $VERSION_CODENAME main restricted
deb-src https://repository.cache.walmart.com/repository/ubuntu-archive/ $VERSION_CODENAME main restricted
deb https://repository.cache.walmart.com/repository/ubuntu-archive/ ${VERSION_CODENAME}-updates main restricted
deb-src https://repository.cache.walmart.com/repository/ubuntu-archive/ ${VERSION_CODENAME}-updates main restricted
deb https://repository.cache.walmart.com/repository/ubuntu-security/ ${VERSION_CODENAME}-security main restricted
deb-src https://repository.cache.walmart.com/repository/ubuntu-security/ ${VERSION_CODENAME}-security main restricted
EOF
fi
  # Clean Cache and re-index from new repos
  apt-get clean
  apt -y update
}

function add_yum_repos {
  image=$1
  if [[ $image =~ ^(centos|rhel).*$ ]];
  then
    # Add Internal WMT Yum Repos
    find /etc/yum.repos.d -name "CentOS*" -delete
    find /etc/yum.repos.d -name "epel*" -delete

    # Add Centos Repos - RHEL repos on GCP work fine
    if [[ $image =~ 'centos' ]];
    then
cat <<'EOF' > /etc/yum.repos.d/CentOS-Base.repo
# CentOS-Base.repo
#

[base]
name=CentOS-$releasever - Base
baseurl=https://repository.cache.cloud.wal-mart.com/content/repositories/centos-$releasever/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-$releasever

EOF

cat <<'EOF' > /etc/yum.repos.d/CentOS-updates.repo
# CentOS-updtes.repo
#

[updates]
name=CentOS-$releasever - Updates
baseurl=https://repository.cache.cloud.wal-mart.com/content/repositories/centos-$releasever/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-$releasever
EOF

cat <<'EOF' > /etc/yum.repos.d/CentOS-extras.repo
# CentOS-Base.repo
#

#additional packages that may be useful
[extras]
name=CentOS-$releasever - Extras
baseurl=https://repository.cache.cloud.wal-mart.com/content/repositories/centos-$releasever/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-$releasever
EOF

cat <<'EOF' > /etc/yum.repos.d/CentOS-plus.repo
# CentOS-Base.repo
#

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-$releasever - Plus
baseurl=https://repository.cache.cloud.wal-mart.com/content/repositories/centos-$releasever/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-$releasever
EOF
    # End of adding CentOS repos
    fi

# Add epel to centos/rhel
cat <<'EOF' > /etc/yum.repos.d/epel.repo
# EPEL.repo
#

[epel]
name=Extra Packages for Enterprise Linux $releasever - $basearch
baseurl=https://repository.cache.cloud.wal-mart.com/content/repositories/fedoraproject-epel-7/$basearch/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
EOF
  # Clean and remake Yum cache
  yum clean all
  yum makecache
fi
# End Section for Adding CentOS Repos
}

function install_auditd {
  # Install Auditd
  install_cmd="$1"
  check_cmd="$2"
  restart_cmd="$3"
  if [[ ! $($check_cmd) ]];
  then
    $install_cmd

    # Setup auditd config
    if [[ ! -d /etc/audit ]];
    then
      mkdir /etc/audit
      mkdir -p "${auditd_rules_dir}"
    fi

    # Create Rules/Conf files if not already defined
    file "$AUDITD_CONF_FILE" || touch "$AUDITD_CONF_FILE"
    file "$AUDITD_RULES_FILE" || touch "$AUDITD_RULES_FILE"

    cat <<EOF > "$AUDITD_CONF_FILE"
#
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = incremental
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = none
max_log_file = 6
max_log_file_action = rotate
space_left = 75
space_left_action = syslog
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = suspend
disk_full_action = suspend
disk_error_action = suspend
tcp_listen_queue = 5

tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF

    # Setup audit rules
    cat <<EOF > "$AUDITD_RULES_FILE"
# Default Rule - Delete ALL
-D

# Set Buffer size - increase for Busy Systems
-b 8192

-a exit,always -F arch=b64 -F auid>=1000 -F auid!=unset -F euid=0 -S execve -k 10.2.2-all-root-commands
-a always,exit -F path=/usr/sbin/aulastlogin -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F path=/bin/aulastlogin -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F path=/bin/auvirt -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F path=/usr/sbin/auvirt -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F path=/usr/bin/su -F perm=x -F key=10.2.5.b-elevated-privs-session
-a always,exit -F path=/usr/bin/sudo -F perm=x -F key=10.2.5.b-elevated-privs
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=10.2.5.b-elevated-privs-setuid
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=10.2.5.b-elevated-privs-setuid
-a always,exit -F path=/etc/group -F perm=wa -F key=10.2.5.c-accounts
-a always,exit -F path=/etc/passwd -F perm=wa -F key=10.2.5.c-accounts
-a exit,always -F arch=b32 -F auid>=1000 -F auid!=unset -F euid=0 -S execve -k 10.2.2-all-root-commands
-a always,exit -F path=/etc/gshadow -F perm=wa -F key=10.2.5.c-accounts
-a always,exit -F path=/etc/shadow -F perm=wa -F key=10.2.5.c-accounts
-a always,exit -F path=/etc/security/opasswd -F perm=wa -F key=10.2.5.c-accounts
-a always,exit -F path=/sbin/insmod -F perm=x -F key=kernel-mod
-a always,exit -F path=/sbin/rmmod -F perm=x -F key=kernel-mod
-a always,exit -F path=/sbin/modprobe -F perm=x -F key=kernel-mod
-a always,exit -F path=/etc/rsyslog.conf -F perm=wa -F key=syslog-mod
-a always,exit -F path=/etc/audit/auditd.conf -F perm=wa -F key=audit-mod
-a always,exit -F path=/etc/audit/audit.rules -F perm=wa -F key=audit-mod
-a always,exit -F path=/etc/audit/rules.d/puppet.rules -F perm=wa -F key=audit-mod
-a always,exit -F dir=/var/log -F perm=r -F auid>=1000 -F auid!=unset -F key=10.2.3-access-audit-trail
-a always,exit -F path=/etc/resolv.conf -F perm=wa -F key=system-mod
-a always,exit -F path=/etc/libuser.conf -F perm=wa -F key=system-mod
-a always,exit -F path=/etc/localtime -F perm=wa -F key=time-change-mod
-a always,exit -F path=/etc/login.defs -F perm=wa -F key=system-mod
-a always,exit -F path=/etc/securetty -F perm=wa -F key=system-mod
-a always,exit -F path=/etc/crontab -F perm=wa -F key=cron-mod
-a always,exit -F path=/etc/anacrontab -F perm=wa -F key=cron-mod
-a always,exit -F path=/etc/cron.allow -F perm=wa -F key=cron-mod
-a always,exit -F path=/etc/cron.deny -F perm=wa -F key=cron-mod
-a always,exit -F dir=/etc/cron.d -F perm=wa -F key=cron-mod
-a always,exit -F path=/usr/sbin/ausearch -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F dir=/etc/cron.hourly -F perm=wa -F key=cron-mod
-a always,exit -F dir=/etc/cron.weekly -F perm=wa -F key=cron-mod
-a always,exit -F dir=/etc/cron.monthly -F perm=wa -F key=cron-mod
-a always,exit -F dir=/etc/profile.d -F perm=wa -F key=shell-mod
-a always,exit -F path=/etc/profile -F perm=wa -F key=shell-mod
-a always,exit -F path=/etc/shells -F perm=wa -F key=shell-mod
-a always,exit -F path=/etc/bashrc -F perm=wa -F key=shell-mod
-a always,exit -F path=/etc/csh.cshrc -F perm=wa -F key=shell-mod
-a always,exit -F path=/etc/csh.login -F perm=wa -F key=shell-mod
-a always,exit -F path=/etc/sysctl.conf -F perm=wa -F key=kernel-mod
-a always,exit -F path=/bin/ausearch -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F dir=/etc/modprobe.d -F perm=wa -F key=kernel-mod
-a always,exit -F path=/etc/ld.so.conf -F perm=wa -F key=kernel-mod
-a always,exit -F dir=/etc/ld.so.conf.d -F perm=wa -F key=kernel-mod
-a always,exit -F path=/etc/inittab -F perm=wa -F key=init-mod
-a always,exit -F path=/etc/rc.local -F perm=wa -F key=init-mod
-a always,exit -F path=/etc/rc.sysinit -F perm=wa -F key=init-mod
-a always,exit -F path=/etc/fstab -F perm=wa -F key=filesystem-mod
-a always,exit -F path=/etc/exports -F perm=wa -F key=filesystem-mod
-a always,exit -F path=/usr/sbin/aureport -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F path=/etc/hosts.allow -F perm=wa -F key=tcpwrapper-mod
-a always,exit -F path=/etc/hosts.deny -F perm=wa -F key=tcpwrapper-mod
-a always,exit -F path=/etc/ssh/sshd_config -F perm=wa -F key=sshd-mod
-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F key=sudo_access-mod
-a always,exit -F path=/etc/sudoers -F perm=wa -F key=sudo_access-mod
-a always,exit -F path=/etc/issue -F perm=wa -F key=banner-mod
-a always,exit -F path=/etc/issue.net -F perm=wa -F key=banner-mod
-a always,exit -F dir=/etc/pam.d -F perm=wa -F key=session-mod
-a always,exit -F dir=/bin -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F dir=/sbin -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F path=/bin/aureport -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F dir=/usr/bin -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F dir=/usr/sbin -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F dir=/lib -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F dir=/usr/lib -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F dir=/lib64 -F perm=wa -F key=10.2.7-system-level-objects
-a always,exit -F path=/bin/aulast -F perm=x -F key=10.2.3-access-audit-trail
-a always,exit -F path=/usr/sbin/aulast -F perm=x -F key=10.2.3-access-audit-trail
EOF

    $restart_cmd
  fi
}


function install_logging_agent {
  ###################################################################################
  # Install & Configure Stackdriver/Fluentd Logging Agent
  # Retrieve Install Script
  cd /root
  curl -ksSO "${URL_PATH}/${LOGGING_SCRIPT_NAME}"
  # Execute Install Script
  bash -ex $INSTALL_SCRIPT_PATH
  cat <<EOF > /etc/google-fluentd/config.d/auditd.conf
<source>
  @type tail

  # Collect the entire line as 'message'
  format /^(?<message>.*)$/

  path /var/log/audit/audit.log
  pos_file /var/tmp/fluentd.auditd.pos
  read_from_head true
  tag os-audit
</source>
EOF

  systemctl enable google-fluentd
  systemctl restart google-fluentd
}

function enable_ntp {
  service_name=$1
  ntp_command=$2
  $ntp_command
  # Enable NTPD daemon
  systemctl enable "$service_name"
  systemctl restart "$service_name"
}


# Main Program
function main {
  # Profile Host

  if [[ -f '/etc/redhat-release' ]];
  then
    # Check for Internal/External Name Resolution
    network_service='network'
    dhcp_client_conf_file='/etc/dhclient.conf'
    package_provider="rpm"
    provider_conf_file="/etc/yum.conf"
    ntp_service='ntpd'
    ntp_install_cmd='yum -y install ntp'
    dns_update_cmd="chkconfig --add $DNS_SCRIPT_PATH"
    dns_install_cmd='yum -y install bind-utils'
    auditd_install_cmd='yum -y install audit'
    auditd_check_cmd='rpm -q audit'
    auditd_restart='/sbin/service auditd restart'
  elif [[ -f '/etc/os-release' ]];
  then
    # Check for Ubuntu Service Naming
    if [[ $(systemctl list-unit-files | grep networkd | grep enabled) ]];
    then
      network_service='systemd-networkd'
      set_resolverd
    else
      network_service='networking'
    fi
    dhcp_client_conf_file='/etc/dhcp/dhclient.conf'
    package_provider="apt"
    provider_conf_file="/etc/apt/apt.conf"
    ntp_service='ntp'
    ntp_install_cmd='apt -y install ntp'
    dns_update_cmd="update-rc.d gcp_dns_update.sh defaults"
    dns_install_cmd='apt -y install dnsutils'
    auditd_install_cmd='apt -y install auditd'
    auditd_check_cmd='dpkg -l auditd'
    if [[ -f '/sbin/service' ]];
    then
      auditd_restart='/sbin/service auditd restart'
    else
      auditd_restart='/usr/sbin/service auditd restart'
    fi
  else
    echo 'Unsupported Operating System'
    echo 'This Script is only supported on RedHat/CentOS and Debian Systems'
    echo 'Exiting'
    exit 1
  fi

  # Check for Internal/External Name Resolution
  add_dhclient_options "$dhcp_client_conf_file" "$network_service"

  # Set Package Provider Proxy
  set_proxy "$package_provider" "$provider_conf_file"

  # Setup CentOS repos if necessary
  if [[ "$package_provider" == "rpm" ]];
  then
    add_yum_repos "$IMAGE"
  elif [[ "$package_provider" == "apt" ]];
  then
    add_apt_repos
  fi

  # Set Hostname
  set_hostname "$package_provider"

  # Add DDNS Script
  add_ddns_script "$dns_update_cmd" "$package_provider" "$dns_install_cmd"

  # Install Auditd
  install_auditd "$auditd_install_cmd" "$auditd_check_cmd" "$auditd_restart"

  # Install fluentd logging agent
  install_logging_agent

  # Enable NTP
  if [[ ! $(dpkg -l chrony) ]];
  then
    enable_ntp "$ntp_service" "$ntp_install_cmd"
  fi
  
  # Touch sentinel file to alert other downstream processes and prevent race conditions
  touch /tmp/gcp-gce-custom-setup-complete
}

# Program Invocation
main
