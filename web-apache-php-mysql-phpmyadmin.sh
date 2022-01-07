#!/bin/sh -eu

# Common
yum -y install kernel kernel-devel
yum -y update
yum -y install epel-release.noarch


# Apache
yum -y install httpd httpd-devel

cat << EOF > /etc/httpd/conf.d/httpd.additional.conf
<Directory "/var/www/html">
    Options Includes FollowSymLinks
    AllowOverride All
</Directory>

DirectoryIndex index.html index.php
EOF

rm -f /etc/httpd/conf.d/welcome.conf

systemctl start httpd
systemctl enable httpd


# PHP
yum -y --enablerepo=epel install php
yum -y --enablerepo=epel install php-devel
yum -y --enablerepo=epel install php-mbstring
yum -y --enablerepo=epel install php-mysql

systemctl restart httpd


# MySQL
curl -sS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash
yum -y install mariadb mariadb-server

cat << EOF > /etc/my.cnf.d/default-character-set.cnf
[server]
character-set-server=utf8mb4

[client]
default-character-set=utf8mb4
EOF

systemctl start mariadb
systemctl enable mariadb


# PHPMyAdmin
yum -y --enablerepo=epel,remi install phpMyAdmin

cat << EOF > /etc/httpd/conf.d/phpMyAdmin_additional.conf
<Directory /usr/share/phpMyAdmin/>
    AllowOverride All
    <IfModule mod_authz_core.c>
        # Apache 2.4
        # Require local
        Require all granted
    </IfModule>
    <IfModule !mod_authz_core.c>
        # Apache 2.2
        Order Deny,Allow
        Deny from None
        Allow from All
    </IfModule>
</Directory>
EOF

cat << EOF >> /etc/phpMyAdmin/config.inc.php

\$cfg['Servers'][\$i]['AllowNoPassword'] = true;
\$cfg['Servers'][\$i]['AllowRoot'] = true;
\$cfg['AllowUserDropDatabase'] = true; 
?>
EOF

mysql -u root < /usr/share/phpMyAdmin/sql/create_tables.sql
cat << EOF | mysql -u root
grant all on phpmyadmin.* to pma@localhost identified by "pmapass";
flush privileges;
drop database test;
EOF

systemctl restart mariadb
systemctl restart httpd
