#!/bin/bash

# iptables script to secure Linux server
# created by SecureTik Team - 

if [ "$EUID" -ne 0 ]; then
  echo "[-] You must run this script as root"
  exit 1
fi

# Ask the user to enter SSH port, default to 2410 if empty
read -p "Enter new SSH port (leave empty for default 2410): " SSH_PORT
SSH_PORT=${SSH_PORT:-2410}
echo "[+] Selected SSH port: $SSH_PORT"

# Automatically detect the network interface with an IP in the 192.168.1.x subnet
INTERFACE=$(ip -o -4 addr show | grep "192.168.1." | awk '{print $2}' | head -n1)

# If no interface found, exit with error
if [ -z "$INTERFACE" ]; then
  echo "[-] No network interface found with IP in 192.168.1.x subnet."
  exit 1
fi

echo "[+] Using network interface: $INTERFACE"

# Reset all rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow established sessions
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH on the selected port with rate limiting (3 new connections per minute)
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# SSH logging
sudo iptables -I INPUT -p tcp --dport 2410 -m conntrack --ctstate NEW -j LOG --log-prefix "SECURETIK-SSH-ACCESS: " --log-level 7
iptables -A INPUT -p tcp --dport 2410 -j LOG --log-prefix "SECURETIK-SSH-DROP: " --log-level 7
iptables -A INPUT -p tcp --dport 2410 -j DROP

# IPTables drop log
sudo iptables -R INPUT 20 -j LOG --log-prefix "IPTables-Dropped: " --log-level 7

# Log and allow ping from 8.8.8.8
sudo iptables -I INPUT 1 -p icmp -s 8.8.8.8 --icmp-type 8 -j LOG --log-prefix "SECURETIK-TEST: " --log-level 7
sudo iptables -I INPUT 2 -p icmp -s 8.8.8.8 --icmp-type 8 -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 5/s -j ACCEPT

# Prevent IP spoofing
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# Prevent known attacks
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT     # SYN Flood
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP                              # XMAS Scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP                             # NULL Scan

# Allow internal network
iptables -A INPUT -i $INTERFACE -s 192.168.1.0/24 -j ACCEPT

# Log rejected attempts (optional)
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 7

echo "[+] All rules applied"

# Save rules
iptables-save > /etc/iptables/rules.v4
echo "[+] Rules saved to /etc/iptables/rules.v4"

