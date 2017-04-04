#!/bin/bash
# Name: centos_mail_secure.sh
# Author: Anthony
# Website: Anthonys.io
# Twitter: Twitter.com/tech
# Purpose: This is used on a Centos machine for quick securing.

###GUI install::
#yum groupinstall "Desktop"
#Re-edit the /etc/inittab file and revert your previous modification. Change id:5:initdefault back to id:3:initdefault.
#https://exemen.wordpress.com/2011/01/16/mail-server-setup-guide-for-rhelcentos-5/

HOSTNAME=1l11l1lll1l1l1l1l1l1llll1lll1l1ll111l1ll1ll1l11l1ll111l1lll1l1l1l1lll1l1l1l1ll1ll1111l
SSHPORT=8081
USER=ant
#PASSWORD=cdc
ROOTPW=newpass

# Change root password
echo -e "$ROOTPW\n$ROOTPW" | passwd root

#setting hostname
echo "$HOSTNAME" > /etc/hostname
hostname -F /etc/hostname

#Securing Partitioin Mounts
echo "/dev/mapper/lg_os-lv_root /                       xfs     defaults        1 1" >> /etc/fstab
echo "/dev/mapper/lg_data-lv_home /home                   xfs     defaults        1 2" >> /etc/fstab
echo "/dev/mapper/lg_os-lv_tmp /tmp                    xfs     defaults,nosuid,noexec,nodev        1 2" >> /etc/fstab
echo "/dev/mapper/lg_os-lv_var /var                    xfs     defaults,nosuid        1 2" >> /etc/fstab
echo "/dev/mapper/lg_os-lv_var_tmp /var/tmp                xfs     defaults,nosuid,noexec,nodev        1 2" >> /etc/fstab
echo "/dev/mapper/lg_os-lv_var_tmp /var/log                xfs     defaults,nosuid,noexec,nodev        1 2" >> /etc/fstab
echo "/dev/mapper/lg_os-lv_var_tmp /var/log/audit                xfs     defaults,nosuid,noexec,nodev        1 2" >> /etc/fstab
echo "/dev/mapper/lg_data-lv_var_www /var/www                xfs     defaults,nosuid,noexec,nodev        1 2" >> /etc/fstab
echo "/dev/mapper/lg_data-lv_swap swap                    swap    defaults        0 0" >> /etc/fstab
sed -i "s/boot                   ext4    defaults        1 2/boot                   ext4    defaults,nosuid,noexec,nodev        1 2/g" /etc/fstab

#Install NTP
yum install ntp ntpdate
chkconfig ntpd on
ntpdate pool.ntp.org
/etc/init.d/ntpd start

#clearing audit.log
rm /var/log/audit/audit.log
touch /var/log/audit/audit.log

#Setting Permission
chmod 600 /boot/grub2/grub.conf
chmod 700 /root
chmod 700 /dev/shm #mysql
chmod 700 /usr/local/squirrelmail/data #iono
chmod 700 /var/tmp #fuckit
chmod 700 /usr/local/squirrelmail/temp #printer
chmod 600 /tmp/

#set auth for signal user mode
sed -i "s/SINGLE=\/sbin\/sushell/SINGLE=\/sbin\/sulogin/g" /etc/sysconfig/init

#remove ctrl alt del
sed -i "s/exec/#exec/g" /etc/init/control-alt-delete.conf
echo "exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"" >> /etc/init/control-alt-delete.conf

#disable ipv6 usage
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network

#prune idle users
echo "Idle users will be removed after 15 minutes"

#lock down cron
echo "Locking down Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

#sysctl security
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 1280" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf

#remove crap
yum remove xinetd
yum remove telnet-server
yum remove rsh-server
yum remove telnet
yum remove rsh-server
yum remove rsh
yum groupremove "X Window System"

#kernal hardening
sysctl -q -n -w kernel.randomize_va_space=2
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

#prevent logins to accounts with null pw
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth

echo "SSH TYPE SHIT"
echo "=================================================================="

# Remove existing ssh keys
rm -rf ~/.ssh/*

#allow only ssh protocol 2
echo "Protocol 2" /etc/ssh/sshd_config

#disable hsost-based auth
sed -i "s/#HostbasedAuthentication/HostbasedAuthentication/g" /etc/ssh/sshd_config

#change ssh port
sed -i "s/Port 22/Port 8081/g" /etc/ssh/sshd_config

#Disable root ssh login
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config

#Disabling X11 forwarding
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config

#Disabling sshd DNS resolution
echo "UseDNS no" >> /etc/ssh/sshd_config

#disable ssh access via empty passwords
sed -i "s/#PermitEmptyPasswords/PermitEmptyPasswords/g" /etc/ssh/sshd_config

#Do Not Allow SSH Environment Options
sed -i "s/#PermitUserEnvironment/PermitUserEnvironment/g" /etc/ssh/sshd_config

#approved ciphers
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config

echo "=================================================================="

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

echo "Adding new user"
echo "=================================================================="
#Creating primary user
if [ $(id -u) -eq 0 ]; then
	# read -p "Enter username of who can connect via SSH: " USER
	read -s -p "Enter password of user who can connect via SSH: " PASSWORD
	egrep "^$USER" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		echo "$USER exists!"
		exit 1
	else
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
		useradd -s /bin/bash -m -d /home/$USER -U -p $pass $USER
		[ $? -eq 0 ] && echo "$USER has been added to system!" || echo "Failed to add a $USER!"
	fi
else
	echo "Only root may add a user to the system"
	exit 2
fi
echo "=================================================================="

echo "Adding $USER to SSH AllowUsers"
echo "AllowUsers $USER" >> /etc/ssh/sshd_config
echo "Adding $USER to sudoers"
cp /etc/sudoers /etc/sudoers.tmp
chmod 0640 /etc/sudoers.tmp
echo "$USER    ALL=(ALL) ALL" >> /etc/sudoers.tmp
chmod 0440 /etc/sudoers.tmp
cp /etc/sudoers.tmp /etc/sudoers
/etc/init.d/ssh restart


echo "Colorize the shells"
echo "==============================================================="
#Adding a bit of color and formatting to the command prompt
echo '
export PS1="${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
' >> /home/$USER/.bashrc
source /home/$USER/.bashrc

echo "Colorize the shells"
#adding color to root
echo '
export PS1="\[$(tput sgr0)\]"
' >> /root/.bashrc
#export PS1="\[\e[30m\]\\$\[\e[m\]"
source /root/.bashrc

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

#Remove wget, find, nmap, gcc,python, and perl
echo "Remove wget, find, nmap, gcc,python, and perl"
echo "============================================="
echo "============================================="
echo "============================================="
