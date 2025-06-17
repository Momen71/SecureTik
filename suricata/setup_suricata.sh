#!/bin/bash

# Step 1: Update and install dependencies
echo "[+] Installing Suricata dependencies..."
sudo apt update
sudo apt install -y software-properties-common

# Step 2: Add Suricata stable repository
echo "[+] Adding Suricata repository..."
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update

# Step 3: Install Suricata
echo "[+] Installing Suricata..."
sudo apt install -y suricata

# Step 4: List interfaces and ask user
echo ""
echo "[+] Available Network Interfaces:"
ip -o link show | awk -F': ' '{print $2}' | grep -v lo
echo ""
read -p "[?] Enter the interface you want Suricata to monitor (e.g. ens33): " INTERFACE

# Step 5: Update suricata.yaml with the selected interface
echo "[+] Configuring suricata.yaml for interface: $INTERFACE"

CONFIG_FILE="/etc/suricata/suricata.yaml"

# Backup original
sudo cp $CONFIG_FILE ${CONFIG_FILE}.bak

# Replace interface in af-packet section (simple method)
sudo sed -i "s/interface: .*/interface: $INTERFACE/" $CONFIG_FILE

# Optional: Ensure nfqueue block is present (IPS readiness)
sudo bash -c "cat >> $CONFIG_FILE <<EOF

nfqueue:
  - id: 0
    accept-mark: 1
    reject-mark: 2
    bypass: yes
EOF"

# Step 6: Create Suricata systemd service
echo "[+] Creating Suricata systemd service..."

SERVICE_FILE="/etc/systemd/system/suricata.service"

sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Suricata Intrusion Detection Service
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i $INTERFACE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=suricata

[Install]
WantedBy=multi-user.target
EOF

# Step 7: Enable and start the service
echo "[+] Enabling and starting Suricata service..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata

# Final step
echo "[✓] Suricata setup completed and running as a service!"
sudo systemctl status suricata --no-pager
