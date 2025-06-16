#!/bin/bash

# iptables script to secure Linux server
# created by SecureTik Team

if [ "$EUID" -ne 0 ]; then
  echo "[-] You must run this script as root"
  exit 1
fi

# Ask the user to enter SSH port, default to 2410 if empty
read -p "Enter new SSH port (leave empty for default 2410): " SSH_PORT
SSH_PORT=${SSH_PORT:-2410}

echo "[+] Selected SSH port: $SSH_PORT"

# Get the network interface name dynamically (excluding loopback)
NIC=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
echo "[+] Using network interface: $NIC"

echo "[+] Resetting existing rules..."
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

# Allow established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Log ICMP (ping) requests
iptables -A INPUT -p icmp --icmp-type 8 -j LOG --log-prefix "SECURETIK-ICMP: " --log-level 7

# Allow ICMP (ping) with rate limit
iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 5/s --limit-burst 5 -j ACCEPT
# SSH: Log and rate-limit
# 1. Add IP to the recent list
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --set

# 2. If limit exceeded, log and drop
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j LOG --log-prefix "SECURETIK-SSH-DROP: " --log-level 7
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# 3. If limit not exceeded, log and accept
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j LOG --log-prefix "SECURETIK-SSH-ACCESS: " --log-level 7
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (Ping): Log and limit
#iptables -A INPUT -p icmp --icmp-type 8 -j LOG --log-prefix "SECURETIK-ICMP: " --log-level 7
#iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 5/s --limit-burst 5 -j ACCEPT

# Prevent IP Spoofing
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# Prevent common attacks
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT     # SYN flood
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP                              # XMAS scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP                             # NULL scan

# Allow internal traffic from private network
iptables -A INPUT -i $NIC -s 10.0.0.0/8 -j ACCEPT

# Final catch-all log rule
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 7

echo "[+] All rules applied successfully."

# Save rules
iptables-save > /etc/iptables/rules.v4
echo "[+] Rules saved to /etc/iptables/rules.v4"

