#!/bin/bash
# Name: drupal_web_secure.sh
# Author: Anthony
# Website: Anthonys.io
# Twitter: Twitter.com/tech
# Purpose: This is used on a ubuntu machine regarding a drupal web server for quick securing.

MYSQLPASSWORD=G3N1U5H4CK5

#SSL SETTINGS
country=US
state=NewYork
locality=NewYork
organization=blueteam
organizationalunit=Hackers
commonname=192.168.1.70 #used for serveral commands.
email=administrator@web.com
#Optional
passwordssl=G3N1U5H4CK5
#SSL SETTINGS END

echo "==============================================================================="
echo "Changing Samba Login/Password"
sed -ie 's/asdfasdf/NEW_USER_FROM_AD_HERE/g' /etc/samba/.smbcredentials
sed -ie 's/ASDFqwer1234/NEW_PASSWORD_HERE/g' /etc/samba/.smbcredentials

#Mysql Changing password (use manual below if this don't work)
mysqladmin -u root -ppassword password 'G3N1U5H4CK5'
mysqladmin -u root -pG3N1U5H4CK5 ping

# If it hangs at Resolving because of using 192 network.. then change /etc/resolv.conf (enable below)
#sed -ie 's/nameserver 10.0.100.1/nameserver 192.168.1.1/g' /etc/resolv.conf

#Puts website in maintenance mode
echo "\$conf['maintenance_mode'] = 1;" >> /var/www/html/sites/default/settings.php

#Download latest drupal updates
cd /var/www/
wget https://ftp.drupal.org/files/projects/drupal-7.54.tar.gz -q
tar -zxf drupal-7.54.tar.gz
mv drupal-7.54 htmlnew
rm drupal-7.54.tar.gz

#Remove infected and unwanted files/folders (pw.list, xmlrpc.php??)
cd /var/www/html
rm README.txt UPGRADE.txt install.php LICENSE.txt INSTALL.mysql.txt INSTALL.pgsql.txt c99shell.php CHANGELOG.txt COPYRIGHT.txt INSTALL.sqlite.txt MAINTAINERS.txt pw.list INSTALL.txt setup.php install.php

#Remove files/folders for the update!
cd /var/www/html
rm -R includes misc modules profiles
rm authorize.php cron.php index.php update.php

#Copying new files over
cd /var/www/html
cp -R /var/www/htmlnew/includes .
cp -R /var/www/htmlnew/misc .
cp -R /var/www/htmlnew/modules .
cp -R /var/www/htmlnew/profiles .
cp -R /var/www/htmlnew/authorize.php .
cp -R /var/www/htmlnew/cron.php .
cp -R /var/www/htmlnew/index.php .
cp -R /var/www/htmlnew/update.php .
cp -R /var/www/htmlnew/install.php .

#Removing extra files..
rm /var/www/html/install.php

#Fix an update permission
sed -ie 's/$update_free_access = TRUE;/$update_free_access = FALSE;/g' /var/www/html/sites/default/settings.php

#Fix file/folder Permissions
cd /var/www/html/sites/default/
chmod 644 settings.php
cd /var/www/html/sites/
chmod -R 755 default

#remove apache2 manual
#rm -R /usr/share/doc/apache2-doc

#Takes website out of maintenance mode
#echo "\$conf['maintenance_mode'] = 0;" >> /var/www/html/sites/default/settings.php
sed -ie "s/] = 1;/] = 0;/g" /var/www/html/sites/default/settings.php

#Need to go to update.php via web.
echo "GO TO WEBSITE.COM/update.php and finish the updates."
echo "GO TO WEBSITE.COM/update.php and finish the updates."
echo "GO TO WEBSITE.COM/update.php and finish the updates."
echo "GO TO WEBSITE.COM/update.php and finish the updates."

#Edit .htaccess in files directory
echo "" >> /var/www/html/sites/default/files/.htaccess
echo "SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006" >> /var/www/html/sites/default/files/.htaccess
echo "<Files *>" >> /var/www/html/sites/default/files/.htaccess
echo "	SetHandler Drupal_Security_Do_Not_Remove_See_SA_2013_003" >> /var/www/html/sites/default/files/.htaccess
echo "</Files>" >> /var/www/html/sites/default/files/.htaccess
echo "<IfModule mod_php5.c>" >> /var/www/html/sites/default/files/.htaccess
echo "  php_flag engine off" >> /var/www/html/sites/default/files/.htaccess
echo "</IfModule>" >> /var/www/html/sites/default/files/.htaccess

#Installing Captcha
wget https://ftp.drupal.org/files/projects/captcha-7.x-1.4.tar.gz -q
tar -zxf captcha-7.x-1.4.tar.gz
cp -R captcha /var/www/html/sites/all/modules
rm -R captcha
rm captcha-7.x-1.4.tar.gz
chmod 775 /var/www/html/sites/all/modules/captcha
echo "Manually enable through modules page, \"user_register_form\""


#Mysql Changing password (use manual below if this don't work)
#mysqladmin -u root -ppassword password '$MYSQLPASSWORD'
#mysqladmin -u root -p$MYSQLPASSWORD ping

#Changing Mysql password on drupal
sed -ie "s/      'password' => 'password',/      'password' => '$MYSQLPASSWORD',/g" /var/www/html/sites/default/settings.php

#/etc/init.d/mysql stop
#Need to do it manually..
#mysql -u root -p
#"Then enter current password"
#use mysql;
#update user set password=PASSWORD("G3N1U5H4CK5") where User='root';
#flush privileges;
#quit
#/etc/init.d/mysql start

#Change Footer
sed -ie "s/devsaran.com/anthonys.io/g" /var/www/html/themes/nexus/templates/page.tpl.php
sed -ie "s/Devsaran/@Tech/g" /var/www/html/themes/nexus/templates/page.tpl.php
sed -ie "s/devsaran.com/anthonys.io/g" /var/www/html/themes/nexus_child/templates/page.tpl.php
sed -ie "s/Devsaran/@Tech/g" /var/www/html/themes/nexus_child/templates/page.tpl.php

#Scrub robots.txt, xmlrpc.php, web.config
mv /var/www/html/robots.txt /var/www/html/robotsNO.txt
mv /var/www/html/xmlrpc.php /var/www/html/xmlrpcNO.php
mv /var/www/html/web.config /var/www/html/webNO.config

#remove apache2 manual
rm -R /usr/share/doc/apache2-doc

#remove apache2 icons
rm -R /usr/share/apache2/icons

#Hide apache version and OS Identity
echo "#Hide apache version and OS Identity" >> /etc/apache2/apache2.conf
echo "ServerSignature Off" >> /etc/apache2/apache2.conf
echo "ServerTokens Prod" >> /etc/apache2/apache2.conf

#Files outside of web root are not served
echo "#Files outside of web root are not served" >> /etc/apache2/apache2.conf
echo "<Directory />" >> /etc/apache2/apache2.conf
echo "  Order Deny,Allow" >> /etc/apache2/apache2.conf
echo "  Deny from all" >> /etc/apache2/apache2.conf
echo "  Options None" >> /etc/apache2/apache2.conf
echo "  AllowOverride None" >> /etc/apache2/apache2.conf
echo "</Directory>" >> /etc/apache2/apache2.conf
echo "<Directory /html>" >> /etc/apache2/apache2.conf
echo "  Order Allow,Deny" >> /etc/apache2/apache2.conf
echo "  Allow from all" >> /etc/apache2/apache2.conf
echo "</Directory>" >> /etc/apache2/apache2.conf

#Turn off apache2 directory browsing
echo "#Turn off apache2 directory browsing" >> /etc/apache2/apache2.conf
echo "<Directory /html>" >> /etc/apache2/apache2.conf
echo "Options -None" >> /etc/apache2/apache2.conf
echo "Options -ExecCGI" >> /etc/apache2/apache2.conf
echo "Options -FollowSymLinks" >> /etc/apache2/apache2.conf
echo "</Directory>" >> /etc/apache2/apache2.conf

#Make sure only root has read access to apache's config and binaries
chown -R root:root /usr/share/apache2/
chmod -R o-rwx /usr/share/apache2/
chown -R root:root /etc/apache2
chmod -R o-rwx /etc/apache2

#restart apache2 service
service apache2 restart

#Remove htmlnew/install.php
rm -R /var/www/htmlnew
rm -R /var/www/html/install.php

echo "==============================================================="
echo "Starting SSL"

#openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt -passin pass:$passwordssl \
    -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"

echo "Done moving on to pem"
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

cat > ssl-params.conf << EOF
# from https://cipherli.st/
# and https://raymii.org/s/tutorials/Strong_SSL_Security_On_Apache2.html

SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3
SSLHonorCipherOrder On
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
#Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains; preload"
Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
# Requires Apache >= 2.4
SSLCompression off 
SSLSessionTickets Off
SSLUseStapling on 
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"
EOF

cp /etc/apache2/sites-available/default-ssl /etc/apache2/sites-available/default-ssl.bak

sed -i '4iServerName '"$commonname" /etc/apache2/sites-available/default-ssl

sed -ie "s/www/www\/html/g" /etc/apache2/sites-available/default-ssl
#sed -ie "s/www/www\/html/g" /etc/apache2/sites-available/default-ssl
#sed -ie "s/webmaster@localhost/\"$email\"/g" /etc/apache2/sites-available/default-ssl

sed -ie "s/AllowOverride None/AllowOverride All/g" /etc/apache2/sites-available/default-ssl
sed -ie "s/AllowOverride None/AllowOverride All/g" /etc/apache2/sites-available/default-ssl
sed -ie "s/AllowOverride None/AllowOverride All/g" /etc/apache2/sites-available/default-ssl

sed -ie "s/ssl-cert-snakeoil.pem/apache-selfsigned.crt/g" /etc/apache2/sites-available/default-ssl
sed -ie "s/ssl-cert-snakeoil.key/apache-selfsigned.key/g" /etc/apache2/sites-available/default-ssl

sed -i '3iRedirect permanent "/" https://'"$commonname/"  /etc/apache2/sites-available/default
a2enmod ssl
a2enmod headers
a2ensite default-ssl
a2enconf ssl-params
apache2ctl configtest
systemctl restart apache2
service apache2 restart

# Reboot the system
##reboot

echo "==============================================================="
echo "Check if website connects to database, if notchange pw in: /var/www/html/sites/default/settings.php "
echo "GO TO WEBSITE.COM/update.php and finish the updates."
echo "Manually enable captcha through modules page, add \"user_register_form\""
echo "Done"
echo "==============================================================="
