# --yum cập nhật
# --Thiết lập người dùng
#   - mật khẩu mở khóa
#   - Xác thực khóa công khai
# - cài đặt ssh
# - cài đặt đồng hồ
# - Cài đặt Phiên bản Máy chủ Bảo vệ
# -- Cài đặt nginx 
# - Cài đặt khóa
# 
# Sau đó, hãy làm điều đó theo cách thủ công
# # Cài đặt nhiều miền
# #Domain SSL (Hãy Mã hóa)
# # Tạo tệp cấu hình vi
# 
# * Đăng ký khóa công khai và thực thi.
# * Kịch bản được mô tả có tham chiếu đến kịch bản được xuất bản trên VPS của Sakura.
# 
# tạo bởi gật đầu. 20201127
# Hệ điều hành có sẵn
# CentOS7 x86_64

#!/bin/bash
set -x;

#環境変数
ADMIN_NAME="@@@ADMIN_NAME@@@"
ADMIN_PASSWORD="@@@ADMIN_PASSWORD@@@"
ADMIN_MAIL="@@@ADMIN_MAIL@@@"
DOMAIN="@@@DOMAIN@@@"
SSH_PORT="@@@SSH_PORT@@@"

# アップデート
yum update -y;
localectl set-locale LANG=ja_JP.utf8;

# logwatch
yum install logwatch -y;
echo -e "MailTo = ${ADMIN_MAIL}\n\nMailFrom = logwatch@${DOMAIN}\n\nDetail = Med" >> /etc/logwatch/conf/logwatch.conf;

# ユーザ設定
useradd ${ADMIN_NAME};
echo ${ADMIN_PASSWORD} | passwd --stdin ${ADMIN_NAME};
usermod -G wheel ${ADMIN_NAME};
echo "${ADMIN_NAME} ALL=NOPASSWD: ALL" | EDITOR='tee -a' visudo >/dev/null;

# 公開鍵認証
mkdir /home/${ADMIN_NAME}/.ssh
mv /root/.ssh/authorized_keys /home/${ADMIN_NAME}/.ssh/authorized_keys
chmod 700 /home/${ADMIN_NAME}/.ssh
chmod 600 /home/${ADMIN_NAME}/.ssh/authorized_keys 
chown ${ADMIN_NAME}:${ADMIN_NAME} /home/${ADMIN_NAME}/.ssh -R

#ssh設定
sed -i -e "s/#PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config;
sed -i -e "s/#Port 22/Port ${SSH_PORT}/" /etc/ssh/sshd_config;
sed -i -e "s/PasswordAuthentication yes/PasswordAuthentication no"
sudo systemctl restart sshd;

#firewalld
systemctl enable firewalld;
systemctl start firewalld;
sed -i -e "s/22/${SSH_PORT}/" /usr/lib/firewalld/services/ssh.xml;
firewall-cmd --reload;

#Siteguard Server Edtion
SGL_VERSION="4.10-0"
SGL_MAJOR_VERSION="4.1.0"
PKGNAME="siteguard-server-edition-${SGL_VERSION}.nginx.x86_64.tar.gz"
NGINX="nginx-1.19.0.tar.gz"

fw_setting
yum clean all
yum install -y glibc perl wget unzip openssl make file java pcre-devel openssl-devel apr-devel  apr-util-devel expect
siteguard_install

nginx_systemd
expect -c "
    spawn ./setup.sh
    set i 0
    while {\$i <= 32} {
    expect -- \"-->\"
    send -- \"\n\"
    incr i 1
    }
"

service_check "nginx"

function fw_setting() {
    FWSTAT=$(systemctl status firewalld.service | awk '/Active/ {print $2}')

    if [ "${FWSTAT}" = "inactive" ]; then
        systemctl start firewalld.service
        firewall-cmd --zone=public --add-service=ssh --permanent
        systemctl enable firewalld.service
    fi
    firewall-cmd --add-service={http,https} --zone=public --permanent
    firewall-cmd --add-port=9443/tcp --zone=public --permanent
    firewall-cmd --reload
}

function service_check() {
    SERVICE=$1

    systemctl status ${SERVICE}.service | grep -q running >/dev/null 2>&1 || systemctl start ${SERVICE}
    for i in {1..5}; do
        sleep 1
        systemctl status ${SERVICE}.service | grep -q running && break
        [ "$i" -lt 5 ] || exit 1
    done
    systemctl enable ${SERVICE}.service || exit 1
}

function siteguard_install() {
    wget -q http://progeny.sakura.ad.jp/siteguard/${SGL_MAJOR_VERSION}/nginx/${PKGNAME} -P /root/.sakuravps
    tar xvzf /root/.sakuravps/${PKGNAME} -C /usr/local/src
    cd /usr/local/src/$(echo ${PKGNAME} | sed 's/.tar.gz//')
    make install || exit 1
    cd ../

    wget -q wget http://nginx.org/download/${NGINX}
    tar xvzf ${NGINX}
    cd $(echo ${NGINX} | sed 's/.tar.gz//')
    ./configure --add-module=/opt/jp-secure/siteguardlite/nginx --with-http_ssl_module
    make
    make install

    cat >/opt/jp-secure/siteguardlite/conf/license.txt <<-EOF
	QNTM-FC2D-J9AY-6838-SWEN
	EOF

    sed -i -e 's/sig_download_user=/sig_download_user=SS9250099/' /opt/jp-secure/siteguardlite/conf/dbupdate_waf.conf
    sed -i -e 's/sig_download_pass=/sig_download_pass=3mtcvD2C/' /opt/jp-secure/siteguardlite/conf/dbupdate_waf.conf

    cat >/opt/jp-secure/siteguardlite/conf/dbupdate_waf_url.conf <<-EOF
	LATEST_URL=https://www.jp-secure.com/download/siteguardlite_sp/updates_lite/latest-lite.zip
	EOF

    cd /opt/jp-secure/siteguardlite/
}

function nginx_initd() {
    echo 'NGINX_CONF_FILE=/usr/local/nginx/conf/nginx.conf' >/etc/sysconfig/nginx

    cat <<-'EOF' >/etc/init.d/nginx
	#!/bin/sh
	#
	# nginx - this script starts and stops the nginx daemon
	#
	# chkconfig:   - 85 15
	# description:  Nginx is an HTTP(S) server, HTTP(S) reverse \
	#               proxy and IMAP/POP3 proxy server
	# processname: nginx
	# config:      /etc/nginx/nginx.conf
	# config:      /etc/sysconfig/nginx
	# pidfile:     /var/run/nginx.pid
	# Source function library.
	. /etc/rc.d/init.d/functions
	# Source networking configuration.
	. /etc/sysconfig/network
	# Check that networking is up.
	[ "$NETWORKING" = "no" ] && exit 0
	nginx="/usr/local/nginx/sbin/nginx"
	prog=$(basename $nginx)
	sysconfig="/etc/sysconfig/$prog"
	lockfile="/var/lock/subsys/nginx"
	pidfile="/usr/local/nginx/logs/${prog}.pid"
	NGINX_CONF_FILE="/usr/local/nginx/conf/nginx.conf"
	[ -f $sysconfig ] && . $sysconfig
	
	start() {
	    [ -x $nginx ] || exit 5
	    [ -f $NGINX_CONF_FILE ] || exit 6
	    echo -n $"Starting $prog: "
	    daemon $nginx -c $NGINX_CONF_FILE
	    retval=$?
	    echo
	    [ $retval -eq 0 ] && touch $lockfile
	    return $retval
	}
	
	stop() {
	    echo -n $"Stopping $prog: "
	    killproc -p $pidfile $prog
	    retval=$?
	    echo
	    [ $retval -eq 0 ] && rm -f $lockfile
	    return $retval
	}
	
	restart() {
	    configtest_q || return 6
	    stop
	    start
	}
	
	reload() {
	    configtest_q || return 6
	    echo -n $"Reloading $prog: "
	    killproc -p $pidfile $prog -HUP
	    echo
	}
	
	configtest() {
	    $nginx -t -c $NGINX_CONF_FILE
	}
	
	configtest_q() {
	    $nginx -t -q -c $NGINX_CONF_FILE
	}
	
	rh_status() {
	    status $prog
	}
	
	rh_status_q() {
	    rh_status >/dev/null 2>&1
	}
	
	# Upgrade the binary with no downtime.
	upgrade() {
	    local oldbin_pidfile="${pidfile}.oldbin"
	
	    configtest_q || return 6
	    echo -n $"Upgrading $prog: "
	    killproc -p $pidfile $prog -USR2
	    retval=$?
	    sleep 1
	    if [[ -f ${oldbin_pidfile} && -f ${pidfile} ]];  then
	        killproc -p $oldbin_pidfile $prog -QUIT
	        success $"$prog online upgrade"
	        echo 
	        return 0
	    else
	        failure $"$prog online upgrade"
	        echo
	        return 1
	    fi
	}
	
	# Tell nginx to reopen logs
	reopen_logs() {
	    configtest_q || return 6
	    echo -n $"Reopening $prog logs: "
	    killproc -p $pidfile $prog -USR1
	    retval=$?
	    echo
	    return $retval
	}
	
	case "$1" in
	    start)
	        rh_status_q && exit 0
	        $1
	        ;;
	    stop)
	        rh_status_q || exit 0
	        $1
	        ;;
	    restart|configtest|reopen_logs)
	        $1
	        ;;
	    force-reload|upgrade) 
	        rh_status_q || exit 7
	        upgrade
	        ;;
	    reload)
	        rh_status_q || exit 7
	        $1
	        ;;
	    status|status_q)
	        rh_$1
	        ;;
	    condrestart|try-restart)
	        rh_status_q || exit 7
	        restart
	            ;;
	    *)
	        echo $"Usage: $0 {start|stop|reload|configtest|status|force-reload|upgrade|restart|reopen_logs}"
	        exit 2
	esac
	EOF

    chmod +x /etc/init.d/nginx
    chkconfig --add nginx
}

function nginx_systemd() {
    cat <<-'EOF' >/etc/systemd/system/nginx.service
	[Unit]
	Description=The nginx HTTP and reverse proxy server
	After=network.target remote-fs.target nss-lookup.target
	
	[Service]
	Type=forking
	PIDFile=/usr/local/nginx/logs/nginx.pid
	ExecStartPre=/usr/bin/rm -f /usr/local/nginx/logs/nginx.pid
	ExecStartPre=/usr/local/nginx/sbin/nginx -t
	ExecStart=/usr/local/nginx/sbin/nginx
	ExecReload=/bin/kill -s HUP $MAINPID
	KillSignal=SIGQUIT
	TimeoutStopSec=5
	KillMode=process
	PrivateTmp=true
	
	[Install]
	WantedBy=multi-user.target
	EOF

    systemctl daemon-reload
}

# Docker install
yum install -y yum-utils device-mapper-persistent-data lvm2
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install -y docker-ce docker-ce-cli containerd.io
systemctl enable docker
systemctl start docker

curl -L https://github.com/docker/compose/releases/download/1.16.1/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
curl -L https://raw.githubusercontent.com/docker/compose/$(docker-compose version --short)/contrib/completion/bash/docker-compose > /etc/bash_completion.d/docker-compose

sh -c "echo -e '##########\nReboot after 10 seconds\n##########' | wall -n; sleep 10; reboot" &
exit 0


# Cài đặt đa miền
# mkdir conf.d
# include conf.d/*;　をnginx.confに追加する
# conf.d/vhost-*.${ADMIN_NAME}.com.conf
# server {
#  listen 80;
#  server_name www.${ADMIN_NAME}.com;
#  return 301 https://$host$request_uri;
#}
#
#server{
#  listen 443 ssl;
#  server_name www.${DOMAIN}.com;
#  
#  ssl_certificate /etc/letsencrypt/live/www.${DOMAIN}/cert.pem;
#  ssl_certificate_key /etc/letsencrypt/live/www.${DOMAIN}/privkey.pem;
#  
#  ssl_prefer_server_ciphers on;
#
#  ssl_buffer_size 4k;
#  
#  keepalive_timeout    70;
#  sendfile             on;
#  client_max_body_size 0;
#
#  proxy_set_header    Host    $host;
#  proxy_set_header    X-Real-IP    $remote_addr;
#  proxy_set_header    X-Forwarded-Host       $host;
#  proxy_set_header    X-Forwarded-Server    $host;
#  proxy_set_header    X-Forwarded-For    $proxy_add_x_forwarded_for;
#
#  location / {
#    # プロキシ先のサーバアドレスとポート番号を指定
#    proxy_pass http://localhost:11000;
#   }
#}

# SSL化
# certbot certonly --webroot -w /usr/local/nginx/html -d *.${DOMAIN} --email ${ADMIN_MAIL}
# http status 200であるかを確認
