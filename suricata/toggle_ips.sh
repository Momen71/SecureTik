#!/bin/bash

echo "=============================="
echo " SecureTik - IPS Mode Toggle"
echo "=============================="

# Check if NFQUEUE rule exists
echo "[*] Checking IPS (NFQUEUE) status..."
if sudo iptables -C FORWARD -j NFQUEUE --queue-num 0 2>/dev/null; then
    echo "[✓] IPS mode is currently: ENABLED"
    CURRENT_STATE="enabled"
else
    echo "[✗] IPS mode is currently: DISABLED"
    CURRENT_STATE="disabled"
fi

echo ""
read -p "[?] Do you want to ENABLE IPS mode? (y/n): " enable_ips

YAML_PATH="/etc/suricata/suricata.yaml"

if [[ "$enable_ips" =~ ^[Yy]$ ]]; then
    echo "[*] Enabling IPS mode..."

    # Step 1: Ensure 'bypass: no' exists
    if grep -qE "^[[:space:]]*bypass:" "$YAML_PATH"; then
        sudo sed -i 's/^[[:space:]]*bypass:.*/  bypass: no/' "$YAML_PATH"
    else
        echo "  bypass: no" | sudo tee -a "$YAML_PATH" > /dev/null
        echo "[+] Added 'bypass: no' to YAML."
    fi

    # Step 2: Ensure 'tpacket_v3: yes' exists
    if grep -qE "^[[:space:]]*tpacket_v3:" "$YAML_PATH"; then
        sudo sed -i 's/^[[:space:]]*tpacket_v3:.*/  tpacket_v3: yes/' "$YAML_PATH"
    else
        echo "  tpacket_v3: yes" | sudo tee -a "$YAML_PATH" > /dev/null
        echo "[+] Added 'tpacket_v3: yes' to YAML."
    fi

    # Step 3: Add iptables rule if not already exists
    if [ "$CURRENT_STATE" = "disabled" ]; then
        echo "[*] Adding iptables NFQUEUE rule..."
        sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
    fi

    # Step 4: Restart Suricata
    echo "[*] Restarting Suricata service..."
    sudo systemctl restart suricata

    echo ""
    echo "[✓] IPS mode enabled successfully."

else
    echo "[*] Disabling IPS mode..."

    # Remove NFQUEUE iptables rule if it exists
    if [ "$CURRENT_STATE" = "enabled" ]; then
        sudo iptables -D FORWARD -j NFQUEUE --queue-num 0 && \
            echo "[✓] NFQUEUE rule removed."
    else
        echo "[!] No NFQUEUE rule found to remove."
    fi

    # Restart Suricata to apply changes
    sudo systemctl restart suricata

    echo "[✓] IPS mode disabled."
fi

