#!/bin/bash
# Name: ubuntu_ftp_secure.sh
# Author: Anthony
# Website: Anthonys.io
# Twitter: Twitter.com/tech
# Purpose: This is used on a ubuntu machine for quick securing.


#/etc/nslcd.conf
#^^LDAP Infomation

ROOTPW=newpass
UBUNTUFTP=newpass
HOSTNAME=111II11I1IIl1llIll11

#192 network stuff
#ifconfig eth0 192.168.1.22 netmask 255.255.255.0
#ip route add default via 192.168.1.1
sed -ie 's/nameserver 10.0.100.1/nameserver 192.168.1.1/g' /etc/resolv.conf
rm /var/lib/apt/lists/* -vf

# Change root password
echo -e "$ROOTPW\n$ROOTPW" | passwd root

#changing default ubuntuftp password
echo -e "$UBUNTUFTP\n$UBUNTUFTP" | passwd ubuntuftp

#Upgrade everything, takes a few seconds (33.9MB)
apt-get -o Acquire::Check-Valid-Until=false update -y -q
apt-get -o Acquire::Check-Valid-Until=false upgrade -y -q

#Removing the folders below
chmod 700 /var/lib/php5 #php
chmod 700 /run/shm #mysql
chmod 700 /run/lock #iono
chmod 700 /var/tmp #fuckit
chmod 700 /tmp #fuckit
chmod 700 /var/spool/samba #printer
chmod 700 /var/crash
chmod 600 /etc/shadow
chmod 700 /var/mail
chmod 700 /tmp/

#Potentional priv escl bullshit
chmod 600 /sys/kernel/security/apparmor/.access
chmod 600 /sys/kernel/security/apparmor/.remove 
chmod 600 /sys/kernel/security/apparmor/.replace
chmod 600 /sys/kernel/security/apparmor/.load

#chmod 700 auth.log for rfis
chmod 700 /var/log/auth.log

# Lock down the sudoers file.
chattr -i /etc/sudoers
echo "root    ALL=(ALL:ALL) ALL" > /etc/sudoers
chmod 000 /etc/sudoers
chattr +i /etc/sudoers

# Clear cronjobs.
chattr -i /etc/crontab
echo "" > /etc/crontab
chattr +i /etc/crontab
chattr -i /etc/anacrontab
echo "" > /etc/anacrontab
chattr +i /etc/anacrontab

# Check programs that have root privliges
find / -perm -04000 > programsWithRootAccess.txt

# Remove existing ssh keys
rm -rf ~/.ssh/*

# Check for users who should not have root privlages.
groupadd -g 3000 badGroup
while read line
do
    IFS=':' read -a userArray <<< "$line"
    if [ ${userArray[0]} != "root" ]
    then
        # Check UID of users
        userID=$(id -u "${userArray[0]}")
        count=3000
        if [  $userID -eq '0' ]
        then
            usermod -u $count ${userArray[0]}
            $count++
        fi

        # Check GID of users
        groupID=$(id -g "${userArray[0]}")
        if [  $groupID -eq '0' ]
        then
            usermod -g 3000 ${userArray[0]}
        fi
    fi
done < '/etc/passwd'

# Remove users from the root group.
rootGroup=$(awk -F':' '/root/{print $4}' /etc/group)
for i in "${rootGroup[@]}"
do
    if [[ $i =~ ^$ ]]
    then
        continue
    fi
    usermod -a -G badGroup $i
    gpasswd -d $i root
done

echo "ssh stuff starting"
echo "==============================================================="

#setting hostname
echo "$HOSTNAME" > /etc/hostname
hostname -F /etc/hostname

#change ssh port
sed -i "s/Port 22/Port 8081/g" /etc/ssh/sshd_config

#Ensure that sshd starts after eth0 is up, not just after filesystem
sed -i "s/start on filesystem/start on filesystem and net-device-up IFACE=eth0/g" /etc/init/ssh.conf

#Disable root ssh login
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config

#Disabling password authentication
#sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config

#Disabling X11 forwarding
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config

#Disabling sshd DNS resolution
echo "UseDNS no" >> /etc/ssh/sshd_config

echo "Linux Kernal Hardening"
echo "==============================================================="
#Linux kernel hardening
#Linux kernel hardening
#Linux kernel hardening
#Linux kernel hardening
cp /etc/sysctl.conf /etc/sysctl.conf.bak
sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.icmp_echo_ignore_broadcasts = 1/net.ipv4.icmp_echo_ignore_broadcasts = 1/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.icmp_ignore_bogus_error_responses = 1/net.ipv4.icmp_ignore_bogus_error_responses = 1/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.log_martians = 1/net.ipv4.conf.all.log_martians = 1/g" /etc/sysctl.conf

#### Fine tuning network parameters for better perfomance
# Change the following parameters when a high rate of incoming connection requests result in connection failures
echo "100000" > /proc/sys/net/core/netdev_max_backlog
# Size of the listen queue for accepting new TCP connections (default: 128)
echo "4096" > /proc/sys/net/core/somaxconn
# Maximum number of sockets in TIME-WAIT to be held simultaneously (default: 180000)
echo "600000" > /proc/sys/net/ipv4/tcp_max_tw_buckets
# sets the Maximum Socket Receive Buffer for all protocols (in bytes)
echo "16777216" > /proc/sys/net/core/rmem_max
echo "16777216" > /proc/sys/net/core/rmem_default
# sets the Maximum Socket Send Buffer for all protocols (in bytes)
echo "16777216" > /proc/sys/net/core/wmem_max
echo "16777216" > /proc/sys/net/core/wmem_default
# Set Linux autotuning TCP buffer limits
echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_rmem
echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_wmem

echo "0" > /proc/sys/net/ipv4/tcp_sack
echo "0" > /proc/sys/net/ipv4/tcp_dsack
# By default, TCP saves various connection metrics in the route cache when the connection closes, so that connections established in the near future can use these to set initial conditions. Usually, this increases overall performance, but may sometimes cause performance degradation. If set, TCP will not cache metrics on closing connections.
echo "1" > /proc/sys/net/ipv4/tcp_no_metrics_save
# How many times to retry before killing an alive TCP connection
echo "5" > /proc/sys/net/ipv4/tcp_retries2
# How often to send TCP keepalive packets to keep an connection alive if it is currently unused. This value is only used when keepalive is enabled
echo "120" > /proc/sys/net/ipv4/tcp_keepalive_time
# How long to wait for a reply on each keepalive probe. This value is in other words extremely important when you try to calculate how long time will go before your connection will die a keepalive death. 
echo "30" > /proc/sys/net/ipv4/tcp_keepalive_intvl
# Determines the number of probes before timing out
echo "3" > /proc/sys/net/ipv4/tcp_keepalive_probes
# How long to keep sockets in the state FIN-WAIT-2 if you were the one closing the socket (default: 60)
echo "30" > /proc/sys/net/ipv4/tcp_fin_timeout
# Sometimes, packet reordering in a network can be interpreted as packet loss and hence increasing the value of this parameter should improve performance (default is “3″)
echo "15" > /proc/sys/net/ipv4/tcp_reordering
#
echo "cubic" > /proc/sys/net/ipv4/tcp_congestion_control
# This value varies depending on total memory of the system. Use it wisely in different situations
# echo "262144" > /proc/sys/net/ipv4/tcp_max_orphans

# Disable Core Dumps
echo "0" > /proc/sys/fs/suid_dumpable
# Enable ExecShield
echo "1" > /proc/sys/kernel/exec-shield
echo "1" > /proc/sys/kernel/randomize_va_space
#### Network parameters for better security
# Disable packet forwarding (if this machine is not a router)
echo "0" > /proc/sys/net/ipv4/ip_forward
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/send_redirects
# Enable tcp_syncookies to accept legitimate connections when faced with a SYN flood attack
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
# Turn off to disable IPv4 protocol features which are considered to have few legitimate uses and to be easy to abuse
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/default/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/all/secure_redirects 
echo "0" > /proc/sys/net/ipv4/conf/default/secure_redirects 
# Log suspicious packets (This should be turned off if the system is suffering from too much logging)
echo "1" > /proc/sys/net/ipv4/conf/all/log_martians
# Protect from ICMP attacks 
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
# Enable RFC-recommended source validation (should not be used on machines which are routers for very complicated networks)
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/default/rp_filter
# Increase IPv4 port range to accept more connections
echo "5000 65535" > /proc/sys/net/ipv4/ip_local_port_range
# Disable IPV6
echo "1" > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo "1" > /proc/sys/net/ipv6/conf/default/disable_ipv6
#### File system tuning 
# Increase system file descriptor limit
echo "7930900" > /proc/sys/fs/file-max
# Allow for more PIDs
echo "65536" > /proc/sys/kernel/pid_max
# Use up to 95% of RAM (5% free)
echo "5" > /proc/sys/vm/swappiness
echo "20" > /proc/sys/vm/dirty_background_ratio
echo "25" > /proc/sys/vm/dirty_ratio



echo "Removing Packages"
echo "==============================================================="
#dpkg --list
#Removing known software!!!!!!!!!!!!!!!!!!! dpkg --list ::to check for more packages
apt-get remove ftp -y
apt-get remove curl -y
#apt-get remove gcc-4.7-base:amd64 -y
#apt-get remove wget -y
apt-get remove telnet -y
apt-get remove telnetd -y

apt-get remove perl -y
apt-get remove perl-base -y
apt-get remove perl-modules -y

apt-get remove netcat-traditional -y
apt-get remove findutils -y

apt-get remove nmap -y
apt-get remove netcat -y
apt-get remove --auto-remove netcat -y
apt-get remove netcat-openbsd -y

#apt-get autoremove -y vsftpd 2>/dev/null
apt-get autoremove -y nmap 2>/dev/null
apt-get autoremove -y telnetd 2>/dev/null
apt-get autoremove -y rdate 2>/dev/null
apt-get autoremove -y tcpdump 2>/dev/null
apt-get autoremove -y vnc4server 2>/dev/null
#apt-get autoremove -y vino 2>/dev/null
apt-get autoremove -y wireshark 2>/dev/null
#apt-get autoremove -y bind9-host 2>/dev/null
#apt-get autoremove -y libbind9-90 2>/dev/null

echo "Removing bash history"
echo "==============================================================="
rm /root/.bash_history

echo "Colorize the shells"
#adding color to root
echo '
export PS1="\[$(tput sgr0)\]"
' >> /root/.bashrc
#export PS1="\[\e[30m\]\\$\[\e[m\]"
source /root/.bashrc

#extra shit
echo "" > /etc/motd
echo "" > /etc/issue.net
chown -f root:root /etc/motd /etc/issue*
chmod -f 0444 /etc/motd /etc/issue*

#Cron setup
if [[ -f /etc/cron.allow ]]; then
  if [[ `grep root /etc/cron.allow 2>/dev/null` != "root" ]]; then
    echo "root" > /etc/cron.allow
    rm -f /etc/at.deny
  else
    echo "root is already in /etc/cron.allow"
    echo ""
  fi
fi

if [[ -f /etc/cron.allow ]]; then
  if [[ ! -f /etc/at.allow ]]; then
    touch /etc/at.allow
  fi
fi

if [[ `grep root /etc/at.allow 2>/dev/null` != "root" ]]; then
  echo "root" > /etc/at.allow
  rm -f /etc/at.deny
else
  echo "root is already in /etc/at.allow"
  echo ""
fi

if [[ `cat /etc/at.deny 2>/dev/null` = "" ]]; then
  rm -f /etc/at.deny
fi

if [[ `cat /etc/cron.deny 2>/dev/null` = "" ]]; then
  rm -f /etc/cron.deny
fi


chmod -f 0700 /etc/cron.monthly/*
chmod -f 0700 /etc/cron.weekly/*
chmod -f 0700 /etc/cron.daily/*
chmod -f 0700 /etc/cron.hourly/*
chmod -f 0700 /etc/cron.d/*
chmod -f 0400 /etc/cron.allow
chmod -f 0400 /etc/cron.deny
chmod -f 0400 /etc/crontab
chmod -f 0400 /etc/at.allow
chmod -f 0400 /etc/at.deny
chmod -f 0700 /etc/cron.daily
chmod -f 0700 /etc/cron.weekly
chmod -f 0700 /etc/cron.monthly
chmod -f 0700 /etc/cron.hourly
chmod -f 0700 /var/spool/cron
chmod -f 0600 /var/spool/cron/*
chmod -f 0700 /var/spool/at
chmod -f 0600 /var/spool/at/*
chmod -f 0400 /etc/anacrontab


#File permissions and ownerships
chmod -f 1777 /tmp
chown -f root:root /var/crash
chown -f root:root /var/cache/mod_proxy
chown -f root:root /var/lib/dav
chown -f root:root /usr/bin/lockfile
chown -f rpcuser:rpcuser /var/lib/nfs/statd
chown -f adm:adm /var/adm
chmod -f 0600 /var/crash
chown -f root:root /bin/mail
chmod -f 0700 /sbin/reboot
chmod -f 0700 /sbin/shutdown
chmod -f 0600 /etc/ssh/ssh*config
chown -f root:root /root
chmod -f 0700 /root
chmod -f 0500 /usr/bin/ypcat
chmod -f 0700 /usr/sbin/usernetctl
chmod -f 0700 /usr/bin/rlogin
chmod -f 0700 /usr/bin/rcp
chmod -f 0640 /etc/pam.d/system-auth*
chmod -f 0640 /etc/login.defs
chmod -f 0750 /etc/security
chmod -f 0600 /etc/audit/audit.rules
chown -f root:root /etc/audit/audit.rules
chmod -f 0600 /etc/audit/auditd.conf
chown -f root:root /etc/audit/auditd.conf
chmod -f 0600 /etc/auditd.conf
chmod -f 0744 /etc/rc.d/init.d/auditd
chown -f root /sbin/auditctl
chmod -f 0750 /sbin/auditctl
chown -f root /sbin/auditd
chmod -f 0750 /sbin/auditd
chmod -f 0750 /sbin/ausearch
chown -f root /sbin/ausearch
chown -f root /sbin/aureport
chmod -f 0750 /sbin/aureport
chown -f root /sbin/autrace
chmod -f 0750 /sbin/autrace
chown -f root /sbin/audispd
chmod -f 0750 /sbin/audispd
chmod -f 0444 /etc/bashrc
chmod -f 0444 /etc/csh.cshrc
chmod -f 0444 /etc/csh.login
chmod -f 0600 /etc/cups/client.conf
chmod -f 0600 /etc/cups/cupsd.conf
chown -f root:sys /etc/cups/client.conf
chown -f root:sys /etc/cups/cupsd.conf
chmod -f 0600 /etc/grub.conf
chown -f root:root /etc/grub.conf
chmod -f 0600 /boot/grub2/grub.cfg
chown -f root:root /boot/grub2/grub.cfg
chmod -f 0600 /boot/grub/grub.cfg
chown -f root:root /boot/grub/grub.cfg
chmod -f 0444 /etc/hosts
chown -f root:root /etc/hosts
chmod -f 0600 /etc/inittab
chown -f root:root /etc/inittab
chmod -f 0444 /etc/mail/sendmail.cf
chown -f root:bin /etc/mail/sendmail.cf
chmod -f 0600 /etc/ntp.conf
chmod -f 0640 /etc/security/access.conf
chmod -f 0600 /etc/security/console.perms
chmod -f 0600 /etc/security/console.perms.d/50-default.perms
chmod -f 0600 /etc/security/limits
chmod -f 0444 /etc/services
chmod -f 0444 /etc/shells
chmod -f 0644 /etc/skel/.*
chmod -f 0600 /etc/skel/.bashrc
chmod -f 0600 /etc/skel/.bash_profile
chmod -f 0600 /etc/skel/.bash_logout
chmod -f 0440 /etc/sudoers
chown -f root:root /etc/sudoers
chmod -f 0600 /etc/sysctl.conf
chown -f root:root /etc/sysctl.conf
chown -f root:root /etc/sysctl.d/*
chmod -f 0700 /etc/sysctl.d
chmod -f 0600 /etc/sysctl.d/*
chmod -f 0600 /etc/syslog.conf
chmod -f 0600 /var/yp/binding
chown -f root:$AUDIT /var/log
chown -Rf root:$AUDIT /var/log/*
chmod -Rf 0640 /var/log/*
chmod -Rf 0640 /var/log/audit/*
chmod -f 0755 /var/log
chmod -f 0750 /var/log/syslog /var/log/audit
chmod -f 0600 /var/log/lastlog*
chmod -f 0600 /var/log/cron*
chmod -f 0600 /var/log/btmp
chmod -f 0660 /var/log/wtmp
chmod -f 0444 /etc/profile
chmod -f 0700 /etc/rc.d/rc.local
chmod -f 0400 /etc/securetty
chmod -f 0700 /etc/rc.local
chmod -f 0750 /usr/bin/wall
chown -f root:tty /usr/bin/wall
chown -f root:users /mnt
chown -f root:users /media
chmod -f 0644 /etc/.login
chmod -f 0644 /etc/profile.d/*
chown -f root /etc/security/environ
chown -f root /etc/xinetd.d
chown -f root /etc/xinetd.d/*
chmod -f 0750 /etc/xinetd.d
chmod -f 0640 /etc/xinetd.d/*
chmod -f 0640 /etc/selinux/config
chmod -f 0750 /usr/bin/chfn
chmod -f 0750 /usr/bin/chsh
chmod -f 0750 /usr/bin/write
chmod -f 0750 /sbin/mount.nfs
chmod -f 0750 /sbin/mount.nfs4
chmod -f 0700 /usr/bin/ldd #0400 FOR SOME SYSTEMS
chmod -f 0700 /bin/traceroute
chown -f root:root /bin/traceroute
chmod -f 0700 /usr/bin/traceroute6*
chown -f root:root /usr/bin/traceroute6
chmod -f 0700 /bin/tcptraceroute
chmod -f 0700 /sbin/iptunnel
chmod -f 0700 /usr/bin/tracpath*
chmod -f 0644 /dev/audio
chown -f root:root /dev/audio
chmod -f 0644 /etc/environment
chown -f root:root /etc/environment
chmod -f 0600 /etc/modprobe.conf
chown -f root:root /etc/modprobe.conf
chown -f root:root /etc/modprobe.d
chown -f root:root /etc/modprobe.d/*
chmod -f 0700 /etc/modprobe.d
chmod -f 0600 /etc/modprobe.d/*
chmod -f o-w /selinux/*
#umask 077 /etc/*
chmod -f 0755 /etc
chmod -f 0644 /usr/share/man/man1/*
chmod -Rf 0644 /usr/share/man/man5
chmod -Rf 0644 /usr/share/man/man1
chmod -f 0600 /etc/yum.repos.d/*
chmod -f 0640 /etc/fstab
chmod -f 0755 /var/cache/man
chmod -f 0755 /etc/init.d/atd
chmod -f 0750 /etc/ppp/peers
chmod -f 0755 /bin/ntfs-3g
chmod -f 0750 /usr/sbin/pppd
chmod -f 0750 /etc/chatscripts
chmod -f 0750 /usr/local/share/ca-certificates

DISA STIG file ownsership
chmod -f 0755 /bin/csh
chmod -f 0755 /bin/jsh
chmod -f 0755 /bin/ksh
chmod -f 0755 /bin/rsh
chmod -f 0755 /bin/sh
chmod -f 0640 /dev/kmem
chown -f root:sys /dev/kmem
chmod -f 0640 /dev/mem
chown -f root:sys /dev/mem
chmod -f 0666 /dev/null
chown -f root:sys /dev/null
chmod -f 0755 /etc/csh
chmod -f 0755 /etc/jsh
chmod -f 0755 /etc/ksh
chmod -f 0755 /etc/rsh
chmod -f 0755 /etc/sh
chmod -f 0644 /etc/aliases
chown -f root:root /etc/aliases
chmod -f 0640 /etc/exports
chown -f root:root /etc/exports
chmod -f 0640 /etc/ftpusers
chown -f root:root /etc/ftpusers
chmod -f 0664 /etc/host.lpd
chmod -f 0440 /etc/inetd.conf
chown -f root:root /etc/inetd.conf
chmod -f 0644 /etc/mail/aliases
chown -f root:root /etc/mail/aliases
chmod -f 0644 /etc/passwd
chown -f root:root /etc/passwd
chmod -f 0400 /etc/shadow
chown -f root:root /etc/shadow
chmod -f 0600 /etc/uucp/L.cmds
chown -f uucp:uucp /etc/uucp/L.cmds
chmod -f 0600 /etc/uucp/L.sys
chown -f uucp:uucp /etc/uucp/L.sys
chmod -f 0600 /etc/uucp/Permissions
chown -f uucp:uucp /etc/uucp/Permissions
chmod -f 0600 /etc/uucp/remote.unknown
chown -f root:root /etc/uucp/remote.unknown
chmod -f 0600 /etc/uucp/remote.systems
chmod -f 0600 /etc/uccp/Systems
chown -f uucp:uucp /etc/uccp/Systems
chmod -f 0755 /sbin/csh
chmod -f 0755 /sbin/jsh
chmod -f 0755 /sbin/ksh
chmod -f 0755 /sbin/rsh
chmod -f 0755 /sbin/sh
chmod -f 0755 /usr/bin/csh
chmod -f 0755 /usr/bin/jsh
chmod -f 0755 /usr/bin/ksh
chmod -f 0755 /usr/bin/rsh
chmod -f 0755 /usr/bin/sh
chmod -f 1777 /var/mail
chmod -f 1777 /var/spool/uucppublic

#Set all files in ``.ssh`` to ``600``
chmod 700 ~/.ssh && chmod 600 ~/.ssh/*

#Disable ctrl-alt-delete RHEL 6+
if [[ -f /etc/init/control-alt-delete.conf ]]; then
  if [[ `grep ^exec /etc/init/control-alt-delete.conf` != "" ]]; then
    sed -i 's/^exec/#exec/g' /etc/init/control-alt-delete.conf
  fi
fi


#Disable ctrl-alt-delete RHEL 5+
if [[ -f /etc/inittab ]]; then
  if [[ `grep ^ca:: /etc/inittab` != "" ]]; then
    sed -i 's/^ca::/#ca::/g' /etc/inittab
  fi
fi

echo "==============================================================="
echo "Removing users!"
userdel -f games 2>/dev/null
userdel -f news 2>/dev/null
userdel -f gopher 2>/dev/null
userdel -f tcpdump 2>/dev/null
userdel -f shutdown 2>/dev/null
userdel -f halt 2>/dev/null
userdel -f sync 2>/dev/null
userdel -f ftp 2>/dev/null
userdel -f operator 2>/dev/null
userdel -f lp 2>/dev/null
userdel -f uucp 2>/dev/null
userdel -f irc 2>/dev/null
userdel -f gnats 2>/dev/null
userdel -f pcap 2>/dev/null
userdel -f netdump 2>/dev/null
userdel -f www-data 2>/dev/null
userdel -f netdump 2>/dev/null

#Disable fingerprint in PAM and authconfig
authconfig --disablefingerprint --update

#Misc settings and permissions
chmod -Rf o-w /usr/local/src/*
rm -f /etc/security/console.perms

#Set background image permissions
chmod -f 0444 /usr/share/backgrounds/default*
chmod -f 0444 /usr/share/backgrounds/images/default*

#Set home directories to 0700 permissions
if [[ -d /home ]]; then
  for x in `find /home -maxdepth 1 -mindepth 1 -type d`; do chmod -f 0700 $x; done
fi

if [[ -d /export/home ]]; then
  for x in `find /export/home -maxdepth 1 -mindepth 1 -type d`; do chmod -f 0700 $x; done
fi

if [[ `which sysctl 2>/dev/null` != "" ]]; then
  #Turn on Exec Shield for RHEL systems
  sysctl -w kernel.exec-shield=1
  #Turn on ASLR Conservative Randomization
  sysctl -w kernel.randomize_va_space=1
  #Hide Kernel Pointers
  sysctl -w kernel.kptr_restrict=1
  #Allow reboot/poweroff, remount read-only, sync command
  sysctl -w kernel.sysrq=176
  #Restrict PTRACE for debugging
  sysctl -w kernel.yama.ptrace_scope=1
  #Hard and Soft Link Protection
  sysctl -w fs.protected_hardlinks=1
  sysctl -w fs.protected_symlinks=1
  #Enable TCP SYN Cookie Protection
  sysctl -w net.ipv4.tcp_syncookies=1
  #Disable IP Source Routing
  sysctl -w net.ipv4.conf.all.accept_source_route=0
  #Disable ICMP Redirect Acceptance
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv6.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv6.conf.all.send_redirects=0
  #Enable IP Spoofing Protection
  sysctl -w net.ipv4.conf.all.rp_filter=1
  sysctl -w net.ipv4.conf.default.rp_filter=1
  #Enable Ignoring to ICMP Requests
  sysctl -w net.ipv4.icmp_echo_ignore_all=0
  #Enable Ignoring Broadcasts Request
  sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
  #Enable Bad Error Message Protection
  sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
  #Enable Logging of Spoofed Packets, Source Routed Packets, Redirect Packets
  sysctl -w net.ipv4.conf.all.log_martians=1
  sysctl -w net.ipv4.conf.default.log_martians=1
  #Perfer Privacy Addresses
  net.ipv6.conf.all.use_tempaddr = 2
  net.ipv6.conf.default.use_tempaddr = 2
  sysctl -p
fi

#last minute shit
rm /var/log/bootstrap.log
#chmod 400 /proc/kallsyms #kernal exploit

echo "==============================================================="
echo "FINISHED!"
echo "FINISHED!"
echo "Done"
echo "==============================================================="
