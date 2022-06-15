get_ipv4(){
    local IP
    IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v '^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\.' | head -n 1 )
    [ -z "${IP}" ] && IP=$( curl -s ipinfo.io/ip )
    [ -z "${IP}" ] && IP=$( curl -s ipv4.ip.sb )
    echo "${IP}"
}

red='\033[0;31m'
green='\033[0;32m'
color='\033[0m'

[ $EUID -ne 0 ] && echo -e "[${red}Error${color}] This script must be run as root!" && exit 1
ufw disable
ip=$(get_ipv4)
# TODO: bug!
domain=$1
[ -z "${ip}" ] && echo -e "[${red}Error${color}] Unable to get server ipv4!" && exit 2
[ -z $domain ] && domain="$ip.nip.io"
echo $domain

interface=$(ip route show default | awk '{print $5}')
[ -z "${interface}" ] && echo -e "[${red}Error${color}] Unable to get the interface!" && exit 3

apt update && apt install strongswan -y
apt install libtss2-tcti-tabrmd0 -y

#TODO: certbot renew hook
apt install snapd -y
snap install core
snap refresh core
snap install --classic certbot
ln -sb /snap/bin/certbot /usr/bin/certbot
certbot certonly --non-interactive --agree-tos --preferred-challenges --register-unsafely-without-email --standalone -d $domain
ln -f -s /etc/letsencrypt/live/$domain/cert.pem    /etc/ipsec.d/certs/server-cert.pem
ln -f -s /etc/letsencrypt/live/$domain/privkey.pem /etc/ipsec.d/private/server-key.pem
ln -f -s /etc/letsencrypt/live/$domain/chain.pem   /etc/ipsec.d/cacerts/chain.pem

echo "/etc/letsencrypt/archive/$domain/* r,
" >> /etc/apparmor.d/local/usr.lib.ipsec.charon

aa-status --enabled && invoke-rc.d apparmor reload

cat > /etc/ipsec.conf<<-EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=$domain
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0,::/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24,fd01:2345:6789:10::/64
    rightdns=8.8.8.8,8.8.4.4,2001:4860:4860::8888, 2001:4860:4860::8844
    rightsendcert=never
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
EOF

cat > /etc/ipsec.secrets<<-EOF
: RSA "server-key.pem"
username : EAP "password"
EOF

systemctl restart strongswan-starter
echo "net.ipv4.conf.all.forwarding = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
sysctl -p

iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -m policy --dir in --pol ipsec -j ACCEPT
iptables -A FORWARD -d 10.10.10.0/24 -m policy --dir out --pol ipsec -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $interface -j MASQUERADE
ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p esp -j ACCEPT
ip6tables -A INPUT -p udp --dport 500 -j ACCEPT
ip6tables -A INPUT -p udp --dport 4500 -j ACCEPT
ip6tables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ip6tables -A FORWARD -s fd01:2345:6789:10::/64 -m policy --dir in --pol ipsec -j ACCEPT
ip6tables -A FORWARD -d fd01:2345:6789:10::/64 -m policy --dir out --pol ipsec -j ACCEPT
ip6tables -t nat -A POSTROUTING -s fd01:2345:6789:10::/64 -o $interface -j MASQUERADE

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt install iptables-persistent -y

echo -e "======================================================"
echo -e "Configure the credential: ${green}vim /etc/ipsec.secrets${color}"
echo -e "And then run: ${green}ipsec rereadsecrets${color}"
echo -e "Domain: ${green}${domain}${color}"
echo -e "======================================================"
