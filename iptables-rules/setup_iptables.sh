#!/bin/bash

# iptables script to secure Linux server
# created by SecureTik Team

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] You must run this script as root"
  exit 1
fi

# Fixed SSH port
SSH_PORT=2410
echo "[+] Using fixed SSH port: $SSH_PORT"

# Get active network interface (excluding loopback)
NIC=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
echo "[+] Using network interface: $NIC"

echo "[+] Resetting existing rules..."
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP (Ping) with rate limit
iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 5/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 8 -j LOG --log-prefix "SECURETIK-ICMP: " --log-level 7

# SSH: Allow and log new connections (Suricata will handle brute-force detection)
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j LOG --log-prefix "SECURETIK-SSH-ACCESS: " --log-level 7
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Anti-spoofing rules
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# SYN flood protection
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT

# Drop suspicious traffic directly (even if Suricata is active)
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP      # XMAS scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP     # NULL scan
iptables -A INPUT -s 224.0.0.0/4 -j DROP                  # Multicast
iptables -A INPUT -s 240.0.0.0/5 -j DROP                  # Reserved

# Allow internal private network traffic (adjust if needed)
iptables -A INPUT -i $NIC -s 10.0.0.0/8 -j ACCEPT

# === Suricata IPS Integration ===
# Send traffic to NFQUEUE for Suricata to inspect
iptables -I INPUT -j NFQUEUE --queue-num 0
iptables -I FORWARD -j NFQUEUE --queue-num 0

# Logging of dropped packets by iptables (optional if Suricata handles it)
# iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 7

echo "[+] All rules applied successfully."

# Save rules
iptables-save > /etc/iptables/rules.v4
echo "[+] Rules saved to /etc/iptables/rules.v4"

