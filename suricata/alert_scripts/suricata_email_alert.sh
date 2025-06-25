#!/bin/bash

# config path
CONFIG_FILE="$HOME/.suricata_email_config"
LOG_FILE="/var/log/suricata/fast.log"
LAST_ALERT=""

# First time setup: ask for email
if [ ! -f "$CONFIG_FILE" ]; then
    echo -n "Enter your email address to receive alerts: "
    read user_email
    echo "$user_email" > "$CONFIG_FILE"
    echo "[+] Email saved in $CONFIG_FILE"
fi

# Load saved email
user_email=$(cat "$CONFIG_FILE")

echo "[*] Monitoring Suricata alerts..."
while true; do
    if [ -f "$LOG_FILE" ]; then
        CURRENT_ALERT=$(tail -n 1 "$LOG_FILE")
        if [ "$CURRENT_ALERT" != "$LAST_ALERT" ]; then
            echo "[ALERT] $CURRENT_ALERT"
            echo -e "Subject: [SURICATA ALERT]\n\n$CURRENT_ALERT" | sendmail "$user_email"
            LAST_ALERT="$CURRENT_ALERT"
        fi
    fi
    sleep 5
done
