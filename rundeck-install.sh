#!/bin/bash

apt update -y 
apt install ansible mc -y
mkdir -p ~/ansible-deployment
cd ~/ansible-deployment
# Create ansible project structure
LOC=`pwd`
mkdir -p $LOC/group_vars
mkdir -p $LOC/host_vars
touch $LOC/main.yaml
mkdir -p $LOC/tasks
mkdir -p $LOC/roles

# Install galaxy collection
#ansible-galaxy collection install community.general

cat <<EOF > $LOC/launcher.yaml
---
- name: Deployment of PoC
  hosts: localhost
  vars:
    nope: nope

  tasks:
  - name: Install loop
    import_tasks: main.yaml
EOF

cat <<EOF > $LOC/host_vars/localhost
---
# file: group_vars/localhost
server_pub_ip: "$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
server_nic: "$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
server_wg_nic: "wg0"
server_wg_ipv4: "10.67.67.1"
server_wg_ipv6: "fd42:42:42::1"
random_port: "37854"
client_dns_1: "1.1.1.1"
client_dns_2: "8.8.8.8"
allowed_ips: "0.0.0.0/0,::/0"
habesbet_passwd: "Passw0rd*"
EOF

cat <<EOF > $LOC/main.yaml
---
- name: Wireguard Installation
  import_tasks: wireguard_install.yaml
- name: NGINX Installation
  import_tasks: nginx_install.yaml
- name: Rundeck Installation
  import_tasks: rundeck_install.yaml
- name: Firewall Installation
  import_tasks: firewall_install.yaml


EOF

cat <<EOF > $LOC/wireguard_install.yaml
---
#- name: Download WG install script
#  get_url:
#    url: https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
#    dest: ${LOC}/wireguard-install.sh
#    mode: '0700'

- name: Make installation file executable
  ansible.builtin.file:
    path: "$LOC/wireguard-install.sh"
    mode: "0700"

- name: Run WG install script
  shell: "${LOC}/wireguard-install.sh {{ server_pub_ip }} {{ server_nic }} {{ server_wg_nic }} {{ server_wg_ipv4 }} {{ server_wg_ipv6 }} {{ random_port }} {{ client_dns_1 }} {{ client_dns_2 }} {{ allowed_ips }}"

EOF

cat <<EOF > $LOC/rundeck_install.yaml
---

EOF

cat <<EOFE > $LOC/wireguard-install.sh
#!/bin/bash
set -x
# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
    if [ "\${EUID}" -ne 0 ]; then
        echo "You need to run this script as root"
        exit 1
    fi
}

function checkVirt() {
    if [ "\$(systemd-detect-virt)" == "openvz" ]; then
        echo "OpenVZ is not supported"
        exit 1
    fi

    if [ "\$(systemd-detect-virt)" == "lxc" ]; then
        echo "LXC is not supported (yet)."
        echo "WireGuard can technically run in an LXC container,"
        echo "but the kernel module has to be installed on the host,"
        echo "the container has to be run with some specific parameters"
        echo "and only the tools need to be installed in the container."
        exit 1
    fi
}

function checkOS() {
    source /etc/os-release
    OS="\${ID}"
    if [[ \${OS} == "debian" || \${OS} == "raspbian" ]]; then
        if [[ \${VERSION_ID} -lt 10 ]]; then
            echo "Your version of Debian (\${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
            exit 1
        fi
        OS=debian # overwrite if raspbian
    elif [[ \${OS} == "ubuntu" ]]; then
        RELEASE_YEAR=\$(echo "\${VERSION_ID}" | cut -d'.' -f1)
        if [[ \${RELEASE_YEAR} -lt 18 ]]; then
            echo "Your version of Ubuntu (\${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
            exit 1
        fi
    elif [[ \${OS} == "fedora" ]]; then
        if [[ \${VERSION_ID} -lt 32 ]]; then
            echo "Your version of Fedora (\${VERSION_ID}) is not supported. Please use Fedora 32 or later"
            exit 1
        fi
    elif [[ \${OS} == 'centos' ]] || [[ \${OS} == 'almalinux' ]] || [[ \${OS} == 'rocky' ]]; then
        if [[ \${VERSION_ID} == 7* ]]; then
            echo "Your version of CentOS (\${VERSION_ID}) is not supported. Please use CentOS 8 or later"
            exit 1
        fi
    elif [[ -e /etc/oracle-release ]]; then
        source /etc/os-release
        OS=oracle
    elif [[ -e /etc/arch-release ]]; then
        OS=arch
    else
        echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
        exit 1
    fi
}

function getHomeDirForClient() {
    local CLIENT_NAME=\$1

    if [ -z "\${CLIENT_NAME}" ]; then
        echo "Error: getHomeDirForClient() requires a client name as argument"
        exit 1
    fi

    # Home directory of the user, where the client configuration will be written
    if [ -e "/home/\${CLIENT_NAME}" ]; then
        # if \$1 is a user name
        HOME_DIR="/home/\${CLIENT_NAME}"
    elif [ "\${SUDO_USER}" ]; then
        # if not, use SUDO_USER
        if [ "\${SUDO_USER}" == "root" ]; then
            # If running sudo as root
            HOME_DIR="/root"
        else
            HOME_DIR="/home/\${SUDO_USER}"
        fi
    else
        # if not SUDO_USER, use /root
        HOME_DIR="/root"
    fi

    echo "\$HOME_DIR"
}

function initialCheck() {
    isRoot
    checkVirt
    checkOS
}

function newClient() {
    local CLIENT_NAME="wireguard"
    # If SERVER_PUB_IP is IPv6, add brackets if missing
    if [[ \${SERVER_PUB_IP} =~ .*:.* ]]; then
        if [[ \${SERVER_PUB_IP} != *"["* ]] || [[ \${SERVER_PUB_IP} != *"]"* ]]; then
            SERVER_PUB_IP="[\${SERVER_PUB_IP}]"
        fi
    fi
    ENDPOINT="\${SERVER_PUB_IP}:\${SERVER_PORT}"
    echo ""
    echo "Client configuration"
    echo ""
    echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."
    until [[ \${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && \${CLIENT_EXISTS} == '0' && \${#CLIENT_NAME} -lt 16 ]]; do
        #read -rp "Client name: " -e CLIENT_NAME
        CLIENT_EXISTS=\$(grep -c -E "^### Client \${CLIENT_NAME}\$" "/etc/wireguard/\${SERVER_WG_NIC}.conf")
        if [[ \${CLIENT_EXISTS} != 0 ]]; then
            echo ""
            echo -e "\${ORANGE}A client with the specified name was already created, please choose another name.\${NC}"
            echo ""
        fi
    done
    for DOT_IP in {2..254}; do
        DOT_EXISTS=\$(grep -c "\${SERVER_WG_IPV4::-1}\${DOT_IP}" "/etc/wireguard/\${SERVER_WG_NIC}.conf")
        if [[ \${DOT_EXISTS} == '0' ]]; then
            break
        fi
    done
    if [[ \${DOT_EXISTS} == '1' ]]; then
        echo ""
        echo "The subnet configured supports only 253 clients."
        exit 1
    fi
    BASE_IP=\$(echo "\$SERVER_WG_IPV4" | awk -F '.' '{ print \$1"."\$2"."\$3 }')
    until [[ \${IPV4_EXISTS} == '0' ]]; do
        #read -rp "Client WireGuard IPv4: \${BASE_IP}." -e -i "\${DOT_IP}" DOT_IP
        CLIENT_WG_IPV4="\${BASE_IP}.\${DOT_IP}"
        IPV4_EXISTS=\$(grep -c "\$CLIENT_WG_IPV4/32" "/etc/wireguard/\${SERVER_WG_NIC}.conf")
        if [[ \${IPV4_EXISTS} != 0 ]]; then
            echo ""
            echo -e "\${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.\${NC}"
            echo ""
        fi
    done
    BASE_IP=\$(echo "\$SERVER_WG_IPV6" | awk -F '::' '{ print \$1 }')
    until [[ \${IPV6_EXISTS} == '0' ]]; do
        #read -rp "Client WireGuard IPv6: \${BASE_IP}::" -e -i "\${DOT_IP}" DOT_IP
        CLIENT_WG_IPV6="\${BASE_IP}::\${DOT_IP}"
        IPV6_EXISTS=\$(grep -c "\${CLIENT_WG_IPV6}/128" "/etc/wireguard/\${SERVER_WG_NIC}.conf")
        if [[ \${IPV6_EXISTS} != 0 ]]; then
            echo ""
            echo -e "\${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.\${NC}"
            echo ""
        fi
    done
    # Generate key pair for the client
    CLIENT_PRIV_KEY=\$(wg genkey)
    CLIENT_PUB_KEY=\$(echo "\${CLIENT_PRIV_KEY}" | wg pubkey)
    CLIENT_PRE_SHARED_KEY=\$(wg genpsk)
    HOME_DIR=\$(getHomeDirForClient "\${CLIENT_NAME}")
    # Create client file and add the server as a peer
    echo "[Interface]
PrivateKey = \${CLIENT_PRIV_KEY}
Address = \${CLIENT_WG_IPV4}/32,\${CLIENT_WG_IPV6}/128
DNS = \${CLIENT_DNS_1},\${CLIENT_DNS_2}
[Peer]
PublicKey = \${SERVER_PUB_KEY}
PresharedKey = \${CLIENT_PRE_SHARED_KEY}
Endpoint = \${ENDPOINT}
AllowedIPs = \${ALLOWED_IPS}" >"\${HOME_DIR}/\${SERVER_WG_NIC}-client-\${CLIENT_NAME}.conf"
    # Add the client as a peer to the server
    echo -e "\n### Client \${CLIENT_NAME}
[Peer]
PublicKey = \${CLIENT_PUB_KEY}
PresharedKey = \${CLIENT_PRE_SHARED_KEY}
AllowedIPs = \${CLIENT_WG_IPV4}/32,\${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/\${SERVER_WG_NIC}.conf"
    wg syncconf "\${SERVER_WG_NIC}" <(wg-quick strip "\${SERVER_WG_NIC}")
    # Generate QR code if qrencode is installed
    if command -v qrencode &>/dev/null; then
        echo -e "\${GREEN}\nHere is your client config file as a QR Code:\n\${NC}"
        qrencode -t ansiutf8 -l L <"\${HOME_DIR}/\${SERVER_WG_NIC}-client-\${CLIENT_NAME}.conf"
        echo ""
    fi
    echo -e "\${GREEN}Your client config file is in \${HOME_DIR}/\${SERVER_WG_NIC}-client-\${CLIENT_NAME}.conf\${NC}"
}


function installWireGuard() {
    # Run setup questions first
    #installQuestions

    SERVER_PUB_IP=\$1
    SERVER_PUB_NIC=\$2
    SERVER_WG_NIC=\$3
    SERVER_WG_IPV4=\$4
    SERVER_WG_IPV6=\$5
    SERVER_PORT=\$6
    CLIENT_DNS_1=\$7
    CLIENT_DNS_2=\$8
    ALLOWED_IPS=\$9

    # Install WireGuard tools and module
    if [[ \${OS} == 'ubuntu' ]] || [[ \${OS} == 'debian' && \${VERSION_ID} -gt 10 ]]; then
        apt-get update
        apt-get install -y wireguard iptables resolvconf qrencode
    elif [[ \${OS} == 'debian' ]]; then
        if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
            echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
            apt-get update
        fi
        apt update
        apt-get install -y iptables resolvconf qrencode
        apt-get install -y -t buster-backports wireguard
    elif [[ \${OS} == 'fedora' ]]; then
        if [[ \${VERSION_ID} -lt 32 ]]; then
            dnf install -y dnf-plugins-core
            dnf copr enable -y jdoss/wireguard
            dnf install -y wireguard-dkms
        fi
        dnf install -y wireguard-tools iptables qrencode
    elif [[ \${OS} == 'centos' ]] || [[ \${OS} == 'almalinux' ]] || [[ \${OS} == 'rocky' ]]; then
        if [[ \${VERSION_ID} == 8* ]]; then
            yum install -y epel-release elrepo-release
            yum install -y kmod-wireguard
            yum install -y qrencode # not available on release 9
        fi
        yum install -y wireguard-tools iptables
    elif [[ \${OS} == 'oracle' ]]; then
        dnf install -y oraclelinux-developer-release-el8
        dnf config-manager --disable -y ol8_developer
        dnf config-manager --enable -y ol8_developer_UEKR6
        dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
        dnf install -y wireguard-tools qrencode iptables
    elif [[ \${OS} == 'arch' ]]; then
        pacman -S --needed --noconfirm wireguard-tools qrencode
    fi
    # Make sure the directory exists (this does not seem the be the case on fedora)
    mkdir /etc/wireguard >/dev/null 2>&1
    chmod 600 -R /etc/wireguard/
    SERVER_PRIV_KEY=\$(wg genkey)
    SERVER_PUB_KEY=\$(echo "\${SERVER_PRIV_KEY}" | wg pubkey)
    # Save WireGuard settings
    echo "SERVER_PUB_IP=\${SERVER_PUB_IP}
SERVER_PUB_NIC=\${SERVER_PUB_NIC}
SERVER_WG_NIC=\${SERVER_WG_NIC}
SERVER_WG_IPV4=\${SERVER_WG_IPV4}
SERVER_WG_IPV6=\${SERVER_WG_IPV6}
SERVER_PORT=\${SERVER_PORT}
SERVER_PRIV_KEY=\${SERVER_PRIV_KEY}
SERVER_PUB_KEY=\${SERVER_PUB_KEY}
CLIENT_DNS_1=\${CLIENT_DNS_1}
CLIENT_DNS_2=\${CLIENT_DNS_2}
ALLOWED_IPS=\${ALLOWED_IPS}" >/etc/wireguard/params
    # Add server interface
    echo "[Interface]
Address = \${SERVER_WG_IPV4}/24,\${SERVER_WG_IPV6}/64
ListenPort = \${SERVER_PORT}
PrivateKey = \${SERVER_PRIV_KEY}" >"/etc/wireguard/\${SERVER_WG_NIC}.conf"
    if pgrep firewalld; then
        FIREWALLD_IPV4_ADDRESS=\$(echo "\${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=\$(echo "\${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        echo "PostUp = firewall-cmd --add-port \${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=\${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=\${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port \${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=\${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=\${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/\${SERVER_WG_NIC}.conf"
    else
        echo "PostUp = iptables -I INPUT -p udp --dport \${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i \${SERVER_PUB_NIC} -o \${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i \${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o \${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i \${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o \${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport \${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i \${SERVER_PUB_NIC} -o \${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i \${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o \${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i \${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o \${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/\${SERVER_WG_NIC}.conf"
    fi
    # Enable routing on the server
    echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf
    sysctl --system
    systemctl start "wg-quick@\${SERVER_WG_NIC}"
    systemctl enable "wg-quick@\${SERVER_WG_NIC}"
    newClient 
    echo -e "\${GREEN}If you want to add more clients, you simply need to run this script another time!\${NC}"
    # Check if WireGuard is running
    systemctl is-active --quiet "wg-quick@\${SERVER_WG_NIC}"
    WG_RUNNING=\$?
    # WireGuard might not work if we updated the kernel. Tell the user to reboot
    if [[ \${WG_RUNNING} -ne 0 ]]; then
        echo -e "\n\${RED}WARNING: WireGuard does not seem to be running.\${NC}"
        echo -e "\${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@\${SERVER_WG_NIC}\${NC}"
        echo -e "\${ORANGE}If you get something like \"Cannot find device \${SERVER_WG_NIC}\", please reboot!\${NC}"
    else # WireGuard is running
        echo -e "\n\${GREEN}WireGuard is running.\${NC}"
        echo -e "\${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@\${SERVER_WG_NIC}\n\n\${NC}"
        echo -e "\${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.\${NC}"
    fi
}

#SERVER_PUB_IP=\$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print \$1}' | head -1)
#SERVER_NIC="\$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
#SERVER_WG_NIC="wg0"
#SERVER_WG_IPV4="10.67.67.1"
#SERVER_WG_IPV6=fd42:42:42::1
#RANDOM_PORT=\$(shuf -i49152-65535 -n1)
#CLIENT_DNS_1="1.1.1.1"
#CLIENT_DNS_2="8.8.8.8"
#ALLOWED_IPS="0.0.0.0/0,::/0"

initialCheck
installWireGuard \$1 \$2 \$3 \$4 \$5 \$6 \$7 \$8 \$9

EOFE

cat <<EOF > $LOC/nginx_install.yaml
---
- name: install nginx
  apt: name=nginx update_cache=yes

- name: install apache2-utils
  apt: name=apache2-utils update_cache=no

- name: Generate SSL certs and move to /etc/certs
  shell: |
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=ET/ST=Ethiopia/L=Addis Ababa/O=HabesBet/OU=none/CN=wireguard.example.com/emailAddress=."
    mkdir -p /etc/certs
    mv cert.pem /etc/certs/
    mv key.pem  /etc/certs/
    chmod 644 /etc/certs/*

- name: Generate .htpasswd file
  shell: |
    htpasswd -b -c /etc/nginx/.htpasswd habesbet {{ habesbet_passwd }}

- name: Copy configuration
  ansible.builtin.copy:
    src: /tmp/default
    dest: /etc/nginx/sites-available/default
    owner: root
    group: root
    mode: '0644'

- name: Restart and enable nginx via SystemD
  ansible.builtin.systemd:
    state: restarted
    enabled: true
    daemon_reload: true
    name: nginx

EOF

cat <<EOF > /tmp/default
server {
       listen       443 ssl http2 default_server;
       listen       [::]:443 ssl http2 default_server;
       server_name  wireguard.example.com;
       root         /var/www/html;
       index index.html index.htm index.nginx-debian.html;

       ssl_certificate "/etc/certs/cert.pem";
       ssl_certificate_key "/etc/certs/key.pem";
       ssl_session_cache shared:SSL:1m;
       ssl_session_timeout  10m;

       location / {
              auth_basic            "Basic Auth";
              auth_basic_user_file  "/etc/nginx/.htpasswd";
       }
#       location / {
#              try_files \$uri \$uri/ =404;
#       }
}

server {
       listen 80 default_server;
       listen [::]:80 default_server;
       return 301 https://\$host\$request_uri;
}

EOF

cat <<EOF > $LOC/rundeck_install.yaml
---
- name: Add gpg key
  shell: |
    curl -L https://packages.rundeck.com/pagerduty/rundeck/gpgkey | sudo apt-key add -

- name: Add Rundeck repos
  shell: |
    echo "" >> /etc/apt/sources.list.d/rundeck.list
    echo "deb https://packages.rundeck.com/pagerduty/rundeck/any/ any main" >> /etc/apt/sources.list.d/rundeck.list
    echo "deb-src https://packages.rundeck.com/pagerduty/rundeck/any/ any main" >> /etc/apt/sources.list.d/rundeck.list

- name: install OpenJDK 11
  apt: name=openjdk-11-jdk update_cache=yes

- name: Switch to Java 11
  shell: |
    update-java-alternatives -s java-1.11.0-openjdk-amd64 2>/dev/null

- name: install Rundeck
  apt: name=rundeck update_cache=no

- name: Configure IP for access and enable Rundeck
  shell: |
    sed -i 's/grails.serverURL=http:\/\/localhost:4440/grails.serverURL=http:\/\/{{ server_pub_ip }}:4440/g' /etc/rundeck/rundeck-config.properties
    systemctl enable rundeckd

- name: Restart Rundeck via SystemD
  ansible.builtin.systemd:
    state: restarted
    daemon_reload: true
    name: rundeckd

EOF

cat <<EOF > $LOC/firewall_install.yaml
---
- name: Install ufw
  apt: name=ufw update_cache=yes

- name: Disable everything and enable UFW
  community.general.ufw:
    state: enabled
    policy: deny

- name: Allow all access to SSH port 
  community.general.ufw:
    rule: allow
    port: '22'
    proto: tcp

- name: Allow all access to Rundeck port 
  community.general.ufw:
    rule: allow
    port: '4440'
    proto: tcp

- name: Allow all access to WireGuard port 
  community.general.ufw:
    rule: allow
    port: '{{ random_port }}'
    proto: tcp

- name: Allow all access to HTTP port 
  community.general.ufw:
    rule: allow
    port: '80'
    proto: tcp

- name: Allow all access to HTTPS port 
  community.general.ufw:
    rule: allow
    port: '443'
    proto: tcp

- name: Restart and enable ufw via SystemD
  ansible.builtin.systemd:
    state: restarted
    enabled: true
    daemon_reload: true
    name: ufw

EOF

ansible-playbook -vv ./launcher.yaml
