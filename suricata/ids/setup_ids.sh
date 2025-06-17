#!/bin/bash

# Suricata Custom Rules Setup Script - SecureTik Team

# Define list of custom rule files
RULE_FILES=(
  "custom.rules"
  "custom_advanced1.rules"
  "custom_advanced2.rules"
  "custom_advanced3.rules"
  "custom_advanced4.rules"
  "custom_advanced5.rules"
)

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] This script must be run as root."
  exit 1
fi

# Step 1: Install Suricata if not present
echo "[+] Checking for Suricata..."
if ! command -v suricata &>/dev/null; then
  echo "[*] Suricata not found. Installing..."
  apt update && apt install -y suricata
else
  echo "[+] Suricata is already installed."
fi

# Step 2: Find Suricata YAML configuration
YAML_PATH=$(find /etc/suricata -name "suricata.yaml" 2>/dev/null | head -n 1)
if [ -z "$YAML_PATH" ]; then
  echo "[-] Could not find suricata.yaml."
  exit 1
fi

# Step 3: Determine rules directory
RULES_DIR=$(grep "default-rule-path" "$YAML_PATH" | awk '{print $2}' | tr -d "\"")
if [ -z "$RULES_DIR" ]; then
  RULES_DIR="/etc/suricata/rules"
fi
echo "[+] Rules directory: $RULES_DIR"

# Step 4: Copy custom rule files
for file in "${RULE_FILES[@]}"; do
  if [ -f "$file" ]; then
    cp "$file" "$RULES_DIR/"
    echo "[+] Copied $file to rules directory"
  else
    echo "[!] Warning: File $file not found!"
  fi
done

# Step 5: Add rule files to suricata.yaml if missing
echo "[*] Ensuring rules are included in suricata.yaml..."
for rulefile in "${RULE_FILES[@]}"; do
  if ! grep -q "$rulefile" "$YAML_PATH"; then
    sed -i "/rule-files:/a \ \ \ \ - $rulefile" "$YAML_PATH"
    echo "[+] Added $rulefile to suricata.yaml"
  else
    echo "[=] $rulefile already present in suricata.yaml"
  fi
done

# Step 6: Prompt for interface
echo
echo "[*] Available network interfaces:"
ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"
echo

read -p "[?] Enter the network interface to monitor (e.g., eth0): " INTERFACE
if ! ip link show "$INTERFACE" &>/dev/null; then
  echo "[-] Interface $INTERFACE not found. Please check and run again."
  exit 1
fi

# Step 7: Test Suricata configuration
echo "[*] Testing Suricata configuration..."
suricata -T -c "$YAML_PATH" -v
if [ $? -ne 0 ]; then
  echo "[-] Configuration test failed! Check suricata.yaml and rules."
  exit 1
fi

# Step 8: Create systemd override to include interface
echo "[+] Configuring Suricata to always start with interface: $INTERFACE"
mkdir -p /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/interface.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c $YAML_PATH -i $INTERFACE --af-packet
EOF

# Step 9: Reload systemd and enable Suricata
echo "[*] Reloading systemd..."
systemctl daemon-reexec
systemctl daemon-reload

echo "[+] Enabling and restarting Suricata..."
systemctl enable suricata
systemctl restart suricata

# Step 10: Confirm service status
echo
systemctl status suricata --no-pager | grep -E "Active:|Main PID:"

echo
echo "[✔] Suricata is now fully configured and running on interface: $INTERFACE"
echo "[✔] It will start automatically on boot with the specified interface and rules."

