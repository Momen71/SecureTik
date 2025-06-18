# SecureTik - Suricata Installer Script

This script installs and configures **Suricata** (an open-source IDS/IPS) with custom rules for the SecureTik project.

## 📦 Features

- Installs Suricata and all required dependencies
- Runs `suricata-update` to fetch default rules
- Prompts user to select the network interface
- Modifies `suricata.yaml` to:
  - Use selected interface
  - Load custom rules and default rules
- Copies custom rule files into Suricata's rules directory
- Enables and starts Suricata as a system service

## 📁 Custom Rule Files

Make sure the following files exist in the same directory as the script:

custom.rules
custom_ips_1.rules
custom_advanced1.rules
custom_advanced2.rules
custom_advanced3.rules
custom_advanced4.rules
custom_advanced5.rules


## 🚀 Usage

1. **Make script executable**:
   ```bash
   chmod +x install_suricata.sh
2. **Run with sudo **:
   sudo ./install_suricata.sh

