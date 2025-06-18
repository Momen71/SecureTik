#!/bin/bash

echo "=============================="
echo " SecureTik - Suricata Installer"
echo "=============================="

# Step 1: Install dependencies
echo "[*] Installing required packages..."
sudo apt update
sudo apt install -y software-properties-common python3-pip jq ethtool curl net-tools

# Step 2: Add Suricata stable PPA and install
echo "[*] Adding Suricata stable PPA..."
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata suricata-update

# Step 3: Ask for interface
echo ""
echo "[*] Available network interfaces:"
ip -brief link | awk '{print $1}'
echo ""
read -p "[?] Enter the interface to monitor (e.g. eth0, ens33): " INTERFACE

# Step 4: Update suricata.yaml with selected interface
YAML_PATH="/etc/suricata/suricata.yaml"
echo "[*] Updating Suricata config to use interface: $INTERFACE"
sudo sed -i "s/interface: .*$/interface: $INTERFACE/" "$YAML_PATH"

# Step 5: Run suricata-update to generate suricata.rules
echo "[*] Running suricata-update to generate default rules..."
sudo suricata-update

# Step 6: Add our custom rules to suricata.yaml (after default suricata.rules)
echo "[*] Registering custom rule files in YAML..."
sudo sed -i '/rule-files:/,/^[^ ]/s/^ *-.*//' "$YAML_PATH" # Clear old rule list
sudo tee -a "$YAML_PATH" > /dev/null <<EOF
rule-files:
  - suricata.rules
  - custom.rules
  - custom_ips_1.rules
  - custom_advanced1.rules
  - custom_advanced2.rules
  - custom_advanced3.rules
  - custom_advanced4.rules
  - custom_advanced5.rules
EOF

# Step 7: Copy custom rules to Suricata rules directory
RULE_DIR="/var/lib/suricata/rules"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Copying custom rule files to $RULE_DIR"
for RULE in custom.rules custom_ips_1.rules custom_advanced{1..5}.rules; do
    if [ -f "$SCRIPT_DIR/$RULE" ]; then
        sudo cp "$SCRIPT_DIR/$RULE" "$RULE_DIR/$RULE"
    else
        echo "[!] Warning: $RULE not found in script directory."
        sudo touch "$RULE_DIR/$RULE"
    fi
done

# Step 8: Test Suricata configuration
echo "[*] Validating Suricata configuration..."
sudo suricata -T -c "$YAML_PATH" -v

# Step 9: Enable and start Suricata as a service
echo "[*] Enabling and starting Suricata service..."
sudo systemctl enable suricata
sudo systemctl restart suricata

# Done
echo ""
echo "[✓] Suricata installed and configured on interface: $INTERFACE"
echo "[✓] Default and custom rules loaded."
echo "[✓] Rule files in: $RULE_DIR"
