#!/bin/sh

# Get the IP address of the Nginx container
NGINX_IP=$(getent hosts nginx_server | awk '{ print $1 }')

# Check if the IP address was found
if [ -z "$NGINX_IP" ]; then
  echo "Failed to resolve nginx_server IP address"
  exit 1
fi

echo "Nginx IP Address: $NGINX_IP"

# Set up iptables to forward traffic to Nginx
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination "$NGINX_IP:443"
iptables -t nat -A POSTROUTING -j MASQUERADE

# Check and remove the stale Suricata PID file, if it exists
if [ -f /var/run/suricata.pid ]; then
  echo "Removing stale Suricata PID file..."
  rm /var/run/suricata.pid
fi

# Configuring suricata interface (https://docs.suricata.io/en/latest/quickstart.html#basic-setup)
IFACE=$(ifconfig -s | grep -v lo | awk '$1 != "Iface"{print $1}')
CIDR="$(ifconfig $IFACE | grep -oP 'inet \K(\d{1,3}\.){3}')0/24"
echo "Configuring suricata to listen on $IFACE ($CIDR)"
sed -i "s|HOME_NET: \"\[[^]]*\]|HOME_NET: \"[$CIDR]|" /etc/suricata/suricata.yaml

# Security considerations (https://docs.suricata.io/en/latest/security.html)
/usr/sbin/useradd --no-create-home --system --shell /sbin/nologin suricata
chgrp -R suricata /etc/suricata
chmod -R g+r /etc/suricata
chgrp -R suricata /var/log/suricata
chmod -R g+rw /var/log/suricata
chgrp -R suricata /var/lib/suricata
chmod -R g+srw /var/lib/suricata
chgrp -R suricata /var/run/suricata
chmod -R g+srw /var/run/suricata

# Update suricata rules and sources
suricata-update update-sources
suricata-update

# Start Suricata in the foreground to keep the container running
suricata -c /etc/suricata/suricata.yaml -i $IFACE --user suricata --group suricata
