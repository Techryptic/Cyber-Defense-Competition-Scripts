#!/bin/bash
# Name: debian_secure.sh
# Author: Anthony
# Website: Anthonys.io
# Twitter: Twitter.com/tech
# Purpose: This is used on a debian machine for quick securing.

sed -ie 's/nameserver 10.0.100.1/nameserver 192.168.1.1/g' /etc/resolv.conf
rm /var/lib/apt/lists/* -vf

HOSTNAME=www-data
SSHPORT=8081
USER=ant
PASSWORD=cdc
ROOTPW=newpass
PUBLICKEY="ssh rsa yada yada do"

# Change root password
echo -e "$ROOTPW\n$ROOTPW" | passwd root

# Verify this script is being run by the root user.
if [ $EUID -ne 0 ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# If you get "E: Could not get lock /var/lib/apt/lists/lock - open (11: Resource temporarily unavailable)" Then enable below.
# Sudo rm /var/lib/apt/lists/* -vf

apt-get -o Acquire::Check-Valid-Until=false update -y -q
    
# Upgrade everything, takes a few seconds (37.3MB)
apt-get -o Acquire::Check-Valid-Until=false upgrade -y -q

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

echo "Adding $USER to SSH AllowUsers"
echo "AllowUsers $USER" >> /etc/ssh/sshd_config
echo "Adding $USER to sudoers"
cp /etc/sudoers /etc/sudoers.tmp
chmod 0640 /etc/sudoers.tmp
echo "$USER    ALL=(ALL) ALL" >> /etc/sudoers.tmp
chmod 0440 /etc/sudoers.tmp
cp /etc/sudoers.tmp /etc/sudoers
/etc/init.d/ssh restart

echo "Adding SSH key"
echo "==============================================================="
echo "Adding ssh key"
#
mkdir /home/$USER/.ssh
touch /home/$USER/.ssh/authorized_keys
echo $PUBLICKEY >> /home/$USER/.ssh/authorized_keys
chown -R $USER:$USER /home/$USER/.ssh
chmod 700 /home/$USER/.ssh
chmod 600 /home/$USER/.ssh/authorized_keys
#
sed -i "s/#AuthorizedKeysFile/AuthorizedKeysFile/g" /etc/ssh/sshd_config
#
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
#apt-get remove gcc-4.7-base:amd64 -y
#apt-get remove wget -y
apt-get remove telnet -y
apt-get remove telnetd -y

apt-get remove perl -y
apt-get remove perl-base -y
apt-get remove perl-modules -y

apt-get remove netcat-traditional -y
apt-get remove findutils -y
#apt-get remove vim -y
#apt-get remove vim-common -y
#apt-get remove vim-runtime -y
#apt-get remove vim-tiny -y
#apt-get remove bash -y
#apt-get remove bash-completion -y

#apt-get remove python -y
#apt-get remove python-apt -y
#apt-get remove python-apt-common -y
#apt-get remove python-chardet -y
#apt-get remove python-debian -y
#apt-get remove python-debianbts -y
#apt-get remove python-fpconst -y
#apt-get remove python-ipy -y
#apt-get remove python-minimal -y
#apt-get remove python-reportbug -y
#apt-get remove python-selinux -y
#apt-get remove python-semanage -y
#apt-get remove python-sepolgen -y
#apt-get remove python-setools -y
#apt-get remove python-soappy -y
#apt-get remove python-support -y
#apt-get remove python2.6 -y
#apt-get remove python2.6-minimal -y
#apt-get remove python2.7 -y
#apt-get remove python2.7-minimal -y

#rm -R /usr/bin/perl
#rm -R /usr/lib/perl
#rm -R /usr/lib/perl5

echo "Disable shell login"
echo "==============================================================="
#Disable logging via /etc/passwd
#sed -i "s/root:\/bin\/bash/root:\/sbin\/nologin/g" /etc/passwd #root
sed -i "s/sbin:\/bin\/sh/sbin:\/sbin\/nologin/g" /etc/passwd #daemon
sed -i "s/bin:\/bin\/sh/bin:\/sbin\/nologin/g" /etc/passwd #bin
sed -i "s/dev:\/bin\/sh/dev:\/sbin\/nologin/g" /etc/passwd #sys
sed -i "s/games:\/bin\/sh/games:\/sbin\/nologin/g" /etc/passwd #games
sed -i "s/man:\/bin\/sh/man:\/sbin\/nologin/g" /etc/passwd #man
sed -i "s/lpd:\/bin\/sh/lpd:\/sbin\/nologin/g" /etc/passwd #lp (printer?)
sed -i "s/mail:\/bin\/sh/mail:\/sbin\/nologin/g" /etc/passwd #mail
sed -i "s/news:\/bin\/sh/news:\/sbin\/nologin/g" /etc/passwd #news
sed -i "s/uucp:\/bin\/sh/uucp:\/sbin\/nologin/g" /etc/passwd #uucp
sed -i "s/bin:\/bin\/sh/bin:\/sbin\/nologin/g" /etc/passwd #proxy
sed -i "s/www:\/bin\/sh/www:\/sbin\/nologin/g" /etc/passwd #www
sed -i "s/backups:\/bin\/sh/backups:\/sbin\/nologin/g" /etc/passwd #backup
sed -i "s/list:\/bin\/sh/list:\/sbin\/nologin/g" /etc/passwd #list
sed -i "s/ircd:\/bin\/sh/ircd:\/sbin\/nologin/g" /etc/passwd #ircd
sed -i "s/gnats:\/bin\/sh/gnats:\/sbin\/nologin/g" /etc/passwd #gnats
sed -i "s/nonexistent:\/bin\/sh/nonexistent:\/sbin\/nologin/g" /etc/passwd #nobody
sed -i "s/libuuid:\/bin\/sh/libuuid:\/sbin\/nologin/g" /etc/passwd #libuuid
sed -i "s/cdc:\/bin\/bash/cdc:\/sbin\/nologin/g" /etc/passwd #cdc

#Remove random CDC account on linux
userdel -r cdc

echo "ssh configs"
echo "==============================================================="
#ssh configs
#https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html
sed -i "s/#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc/#   Ciphers aes256-ctr/g" /etc/ssh/ssh_config
sed -i "s/#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160/#   MACs hmac-sha1/g" /etc/ssh/ssh_config
sed -i "s/#   Protocol 2,1/#   Protocol 2/g" /etc/ssh/ssh_config

#World Writeable Directories for User/Group 'Root'
#http://www.onlineconversion.com/html_chmod_calculator.htm
#Removing the folders below
chmod 700 /var/lib/php5 #php
chmod 700 /run/shm #mysql
chmod 700 /run/lock #iono
chmod 700 /var/tmp #fuckit
chmod 700 /var/spool/samba #printer
chmod 600 /etc/shadow

########################################
#THINGS TO CHECKOUT
cat /etc/samba/.smbcredentials
#username=asdfasdf@pangea.local
#password=ASDFqwer1234
#
#/etc/samba/smb.conf
#########################################

# Reboot the system
#reboot

echo "==============================================================="
echo "FINISHED!"
echo "FINISHED!"
echo "Done"
echo "==============================================================="
