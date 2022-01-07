#!/bin/bash
#Một tập lệnh thiết lập máy chủ thư (Postfix / Dovecot) và màn hình quản trị (Postfix Admin).
#Sau khi tạo máy chủ, bạn có thể sử dụng Postfix Admin bằng cách truy cập "<https: // FQDN / postfixadmin />" từ trình duyệt của mình.
#Cả hai tên máy chủ IMAP / SMTP đều là FQDN.
#
# Hệ điều hành hỗ trợ
# CentOS7 x86_64, CentOS Stream8 x86_64

set -x

DOMAIN="@@@DOMAIN@@@"
ADMIN_NAME="@@@ADMIN_NAME@@@"
ADMIN_PASSWORD="@@@ADMIN_PASSWORD@@@"
DATABASE_PASSWORD="@@@DATABASE_PASSWORD@@@"

ADMIN_EMAIL=${ADMIN_NAME}@${DOMAIN}
hostnamectl set-hostname ${DOMAIN}
VERSION=$(rpm -q centos-release --qf "%{VERSION}")

function retry_command() {
    COMMAND=$1

    sleep 3
    FAIL_COUNT=0
    while [ ${FAIL_COUNT} -lt 5 ]; do
        yum clean all
        ${COMMAND}
        if [ "$?" = "0" ]; then
            break
        else
            FAIL_COUNT=$(( FAIL_COUNT + 1 ))
            sleep 3
        fi
    done
    if [ ${FAIL_COUNT} -eq 5 ]; then
        echo "Command failed five times. So exit."
        exit 1
    fi
}

YUM_COMMAND="yum -y update"
${YUM_COMMAND} || retry_command "${YUM_COMMAND}"

# Dovecot
YUM_COMMAND="yum -y install dovecot dovecot-mysql"
${YUM_COMMAND} || retry_command "${YUM_COMMAND}"

# Postfix/PostfixAdmin
YUM_COMMAND="yum -y install postfix postfix-mysql mariadb-server httpd mod_ssl"
${YUM_COMMAND} || retry_command "${YUM_COMMAND}"

if [ "$VERSION" = "7" ]; then
    rpm -Uvh https://rpms.remirepo.net/enterprise/remi-release-7.rpm
else
    dnf -y install https://rpms.remirepo.net/enterprise/remi-release-8.rpm
    DNF_COMMAND="dnf -y install epel-release"
    ${DNF_COMMAND} || retry_command "${DNF_COMMAND}"
fi

yum clean all

yum -y install php74-php
if [ "$?" != "0" ]; then
    for i in  {1..5}; do
        yum -y install php74-php
        [ "$?" = "0" ] && break
        [ "$i" = "5" ] && exit 1
    done
fi
yum -y install php74-php-{mbstring,imap,mysql} snapd
if [ "$?" != "0" ]; then
    for i in  {1..5}; do
        yum -y install php74-php-{mbstring,imap,mysql}
        [ "$?" = "0" ] && break
        [ "$i" = "5" ] && exit 1
    done
fi
ln -s php74 /usr/bin/php

# Firewall
FWSTAT=$(systemctl status firewalld.service | awk '/Active/ {print $2}')

if [ "${FWSTAT}" = "inactive" ]; then
    systemctl start firewalld.service
    firewall-cmd --zone=public --add-service=ssh --permanent
    systemctl enable firewalld.service
fi

firewall-cmd --permanent --add-port={80,443}/tcp
firewall-cmd --permanent --add-port={25,110,143,465,587,993,995}/tcp
firewall-cmd --reload

# Let's Encrypt(Standalone)
systemctl enable --now snapd.socket || exit 1
systemctl start snapd.service || exit 1
sleep 5

ln -s /var/lib/snapd/snap /snap
snap install core || exit 1
snap refresh core
snap install certbot --classic || exit 1
ln -s /snap/bin/certbot /usr/bin/certbot || exit 1

/usr/bin/certbot -n certonly --standalone --agree-tos -d ${DOMAIN} -m ${ADMIN_EMAIL} --server https://acme-v02.api.letsencrypt.org/directory || exit 1

LD=/etc/letsencrypt/live/${DOMAIN}
CERT=${LD}/fullchain.pem
PKEY=${LD}/privkey.pem
CHAIN=${LD}/chain.pem
PRE_SCRIPT="/etc/letsencrypt/renewal-hooks/pre/stop.sh"
POST_SCRIPT="/etc/letsencrypt/renewal-hooks/post/reload.sh"

if [ ! -f ${CERT} ]; then
    echo "証明書の取得に失敗しました"
    exit 1
fi

snap start --enable certbot.renew || exit 1
sed -i -e "/^server/a pre_hook = ${PRE_SCRIPT}" /etc/letsencrypt/renewal/${DOMAIN}.conf
sed -i -e "/^pre_hook/a post_hook = ${POST_SCRIPT}" /etc/letsencrypt/renewal/${DOMAIN}.conf

echo -e "#!/bin/bash\nsystemctl stop httpd" >${PRE_SCRIPT} && chmod +x ${PRE_SCRIPT}
echo -e "#!/bin/bash\nsystemctl reload postfix dovecot\nsystemctl start httpd" >${POST_SCRIPT} && chmod +x ${POST_SCRIPT}

# PostfixAdmin
cd /srv/
git clone https://github.com/postfixadmin/postfixadmin.git
cd postfixadmin
LATEST_TAG=$(git tag -l | sort -V |  grep -iv 'push\|rc\|beta' | tail -1)
git checkout ${LATEST_TAG}

systemctl start mariadb.service
systemctl enable mariadb.service

/usr/bin/mysqladmin -u root password "${DATABASE_PASSWORD}"

cat <<EOT >/root/.my.cnf
[client]
host	= localhost
user	= root
password = ${DATABASE_PASSWORD}
socket	= /var/lib/mysql/mysql.sock
EOT
chmod 600 /root/.my.cnf

mysql --defaults-file=/root/.my.cnf <<EOC
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
CREATE DATABASE IF NOT EXISTS postfix;
CREATE USER 'postfix'@'localhost' IDENTIFIED BY '$DATABASE_PASSWORD';
GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'localhost';
FLUSH PRIVILEGES;
EOC

SETUP_PASSWORD=$(php -r "echo password_hash(\"${ADMIN_PASSWORD}\", PASSWORD_DEFAULT);")

cat <<_EOF_  > /srv/postfixadmin/config.local.php
<?php
\$CONF['configured'] = true;

\$CONF['default_language'] = 'ja';
\$CONF['database_type'] = 'mysql';
\$CONF['database_user'] = 'postfix';

\$CONF['database_password'] = '${DATABASE_PASSWORD}';
\$CONF['database_name'] = 'postfix';

\$CONF['setup_password'] = '${SETUP_PASSWORD}';

\$CONF['domain_path'] = 'YES';
\$CONF['domain_in_mailbox'] = 'NO';

\$CONF['encrypt'] = 'dovecot:SHA512-CRYPT';

\$CONF['footer_link'] = 'https://${DOMAIN}/postfixadmin/';
\$CONF['footer_text'] = 'Return to ${DOMAIN}/postfixadmin/';
?>

_EOF_

mkdir -p /srv/postfixadmin/templates_c
chown -R apache /srv/postfixadmin/templates_c

# Apache httpd
cat <<_EOF_  > /etc/httpd/conf.d/postfixadmin.conf
Alias /postfixadmin "/srv/postfixadmin/public"
<Directory "/srv/postfixadmin/public">
    DirectoryIndex index.html index.php
    AllowOverride All
    Options FollowSymlinks
    Require all granted
</Directory>
_EOF_

# HTTPS対応
sed -ie "s|^[#\s]*SSLCertificateFile.*$|SSLCertificateFile ${CERT}|" /etc/httpd/conf.d/ssl.conf
sed -ie "s|^[#\s]*SSLCertificateKeyFile.*$|SSLCertificateKeyFile ${PKEY}|" /etc/httpd/conf.d/ssl.conf
sed -ie "s|^[#\s]*SSLCertificateChainFile.*$|SSLCertificateChainFile ${CHAIN}|" /etc/httpd/conf.d/ssl.conf
sed -ie "s|^[#\s]*SSLProtocol.*$|SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1|" /etc/httpd/conf.d/ssl.conf

# 不要な情報表示を隠す
sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/httpd/conf/httpd.conf
sed -i 's/Options -Indexes/#Options -Indexes/' /etc/httpd/conf.d/welcome.conf
sed -i 's|ErrorDocument 403 /.noindex.html|#ErrorDocument 403 /.noindex.html|' /etc/httpd/conf.d/welcome.conf
echo 'ServerTokens ProductOnly' >> /etc/httpd/conf/httpd.conf
echo 'ServerSignature Off' >> /etc/httpd/conf/httpd.conf

# httpsリダイレクト
cat <<_EOF_  > /etc/httpd/conf.d/rewrite.conf
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R,L]
</IfModule>
_EOF_

systemctl start httpd.service
systemctl enable httpd.service

# セットアップ実行
curl -s -o /dev/null -X POST -d "setup_password=${ADMIN_PASSWORD}" -d "submit=setuppw" -L -k "https://$DOMAIN/postfixadmin/setup.php"
# PostfixADminの初期ユーザ登録
/srv/postfixadmin/scripts/postfixadmin-cli admin add ${ADMIN_EMAIL} --superadmin 1 --active 1 --password ${ADMIN_PASSWORD} --password2 ${ADMIN_PASSWORD}
/srv/postfixadmin/scripts/postfixadmin-cli domain add ${DOMAIN}
/srv/postfixadmin/scripts/postfixadmin-cli domain update ${DOMAIN} --mailboxes 0
/srv/postfixadmin/scripts/postfixadmin-cli mailbox add ${ADMIN_EMAIL} --password ${ADMIN_PASSWORD} --password2 ${ADMIN_PASSWORD}

# 転送設定
/srv/postfixadmin/scripts/postfixadmin-cli alias add root@${DOMAIN} --goto ${ADMIN_EMAIL}
/srv/postfixadmin/scripts/postfixadmin-cli alias update abuse@${DOMAIN} --goto ${ADMIN_EMAIL}
/srv/postfixadmin/scripts/postfixadmin-cli alias update hostmaster@${DOMAIN} --goto ${ADMIN_EMAIL}
/srv/postfixadmin/scripts/postfixadmin-cli alias update postmaster@${DOMAIN} --goto ${ADMIN_EMAIL}
/srv/postfixadmin/scripts/postfixadmin-cli alias update webmaster@${DOMAIN} --goto ${ADMIN_EMAIL}

# Postfix
postconf -e smtpd_banner='$myhostname ESMTP'
postconf -e smtp_header_checks='regexp:/etc/postfix/smtp_header_checks'
postconf -e mime_header_checks='regexp:/etc/postfix/mime_header_checks'
postconf -e disable_vrfy_command=yes
postconf -e smtpd_helo_required=yes

postconf -e inet_interfaces=all
postconf -e myhostname=${DOMAIN}
# デフォルト値にドメインが含まれており virtual_mailbox_domains と重複してしまうため, localhost のみで設定する.
postconf -e mydestination='localhost.$mydomain, localhost'
postconf -e relay_domains='$mydestination'
postconf -e virtual_alias_maps='proxy:mysql:/etc/postfix/virtual_alias_maps.cf'
postconf -e virtual_mailbox_domains=proxy:mysql:/etc/postfix/virtual_mailbox_domains.cf
postconf -e virtual_mailbox_maps='proxy:mysql:/etc/postfix/virtual_mailbox_maps.cf'
postconf -e virtual_mailbox_base='/home/vmail'
postconf -e virtual_mailbox_limit=512000000
postconf -e message_size_limit=20480000
postconf -e virtual_minimum_uid=10000
postconf -e virtual_transport=virtual
postconf -e virtual_uid_maps='static:10000'
postconf -e virtual_gid_maps='static:10000'
postconf -e local_transport=virtual
postconf -e local_recipient_maps='$virtual_mailbox_maps'
postconf -e transport_maps='hash:/etc/postfix/transport'

postconf -e smtpd_sasl_auth_enable=yes
postconf -e smtpd_sasl_type=dovecot
postconf -e smtpd_sasl_path='/var/run/dovecot/auth-client'
postconf -e smtpd_recipient_restrictions='permit_auth_destination, permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
# SPAM対策例をコメントで挿入
echo '# smtpd_client_restrictions=permit_mynetworks, reject_rbl_client bl.spamcop.net, reject_rbl_client zen.spamhaus.org, permit' >> /etc/postfix/main.cf
postconf -e smtpd_client_restrictions='permit_mynetworks, reject_unknown_client, permit'
postconf -e smtpd_sender_restrictions='reject_unknown_sender_domain, reject_non_fqdn_sender'
postconf -e smtpd_relay_restrictions='permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
postconf -e smtpd_sasl_security_options=noanonymous
postconf -e smtpd_sasl_tls_security_options='$smtpd_sasl_security_options'
postconf -e smtpd_tls_security_level=may
postconf -e smtpd_tls_auth_only=yes
postconf -e smtpd_tls_received_header=yes
postconf -e smtpd_tls_cert_file=${CERT}
postconf -e smtpd_tls_key_file=${PKEY}
postconf -e smtpd_tls_CAfile='/etc/pki/tls/certs/ca-bundle.crt'
postconf -e smtpd_tls_mandatory_protocols='!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
postconf -e smtpd_tls_protocols='!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
postconf -e smtpd_tls_ask_ccert=yes
postconf -e smtpd_tls_mandatory_ciphers=high
postconf -e smtpd_use_tls=yes
postconf -e smtpd_sasl_local_domain='$mydomain'
postconf -e broken_sasl_auth_clients=yes
postconf -e smtpd_tls_loglevel=1
postconf -e smtp_tls_security_level=may
postconf -e smtp_tls_loglevel=1
postconf -e smtp_tls_mandatory_protocols='!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
postconf -e smtp_tls_protocols='!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'

sed -i 's/^#\(submission.*smtpd$\)/\1/g' /etc/postfix/master.cf
sed -i 's/^#\(smtps.*smtpd$\)/\1 \n -o smtpd_tls_wrappermode=yes\n -o smtpd_sasl_auth_enable=yes/g' /etc/postfix/master.cf

cat <<'_EOF_' > /etc/postfix/smtp_header_checks
/^Received: .*/     IGNORE
/^User-Agent: .*/   IGNORE
_EOF_

cat <<'_EOF_' > /etc/postfix/mime_header_checks
/^Mime-Version:/    IGNORE
_EOF_

cat <<_EOF_  > /etc/postfix/virtual_alias_maps.cf
user = postfix
password = ${DATABASE_PASSWORD}
hosts = localhost
dbname = postfix
table = alias
select_field = goto
where_field = address
_EOF_

cat <<_EOF_  > /etc/postfix/virtual_mailbox_domains.cf
user = postfix
password = ${DATABASE_PASSWORD}
hosts = localhost
dbname = postfix
table = domain
select_field = domain
where_field = domain
_EOF_

cat <<_EOF_  > /etc/postfix/virtual_mailbox_maps.cf
user = postfix
password = ${DATABASE_PASSWORD}
hosts = localhost
dbname = postfix
table = mailbox
select_field = maildir
where_field = username
_EOF_

postmap /etc/postfix/transport
systemctl restart postfix.service
systemctl enable postfix.service

# Dovecot
groupadd -g 10000 vmail
useradd -u 10000 -g vmail -s /usr/bin/nologin -d /home/vmail -m vmail

mkdir -p /home/vmail/${DOMAIN}/${ADMIN_NAME}/{cur,new,tmp}
chown -R vmail. /home/vmail/

sed -i 's/.*!include conf.d\/\*.conf/#&/g' /etc/dovecot/dovecot.conf

cat <<_EOF_  >> /etc/dovecot/dovecot.conf

protocols = imap pop3
auth_mechanisms = plain

passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf
}
userdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf
}

service auth {
    unix_listener auth-client {
        group = postfix
        mode = 0660
        user = postfix
    }
    user = root
}

mail_home = /home/vmail/%d/%n
mail_location = maildir:~

ssl = yes
ssl_cert = <${CERT}
ssl_key = <${PKEY}
ssl_protocols = !SSLv3 !TLSv1 !TLSv1.1

_EOF_

if [ "$VERSION" != "7" ]; then
    sed -i -e 's/^ssl_protocols.*$/ssl_min_protocol = TLSv1.2/' /etc/dovecot/dovecot.conf
    cat <<_EOF_  >> /etc/dovecot/dovecot.conf

service stats {
    unix_listener stats-writer {
        mode = 0666
    }
}
_EOF_
fi

cat <<_EOF_ > /etc/dovecot/dovecot-sql.conf
driver = mysql
connect = host=localhost dbname=postfix user=postfix password=${DATABASE_PASSWORD}
default_pass_scheme = SHA512-CRYPT
user_query = SELECT '/home/vmail/%d/%n' as home, 'maildir:/home/vmail/%d/%n' as mail, 10000 AS uid, 10000 AS gid, concat('dirsize:storage=',  quota) AS quota FROM mailbox WHERE username = '%u' AND active = '1'
password_query = SELECT username as user, password, '/home/vmail/%d/%n' as userdb_home, 'maildir:/home/vmail/%d/%n' as userdb_mail, 10000 as  userdb_uid, 10000 as userdb_gid FROM mailbox WHERE username = '%u' AND active = '1'
_EOF_

systemctl start dovecot.service
systemctl enable dovecot.service

exit 0
