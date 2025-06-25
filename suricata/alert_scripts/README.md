# Suricata Alert Notification Scripts

This folder contains two monitoring scripts that notify you when Suricata generates alerts:

- 📧 **Email Alerts**: Sends new alerts to your Gmail inbox.
- 📲 **Telegram Alerts**: Sends new alerts to a Telegram chat via a bot.

Both scripts continuously monitor Suricata's `fast.log` file and notify you when a new alert appears.

---

## 🔧 Requirements

Install the following packages:

```bash
sudo apt update
sudo apt install sendmail python3 python3-pip -y
pip3 install requests

📁 Files Overview
| File                         | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| `suricata_email_alert.sh`    | Bash script that sends Suricata alerts via Gmail using `sendmail` |
| `suricata_telegram_alert.py` | Python script that sends Suricata alerts to Telegram chat         |
| `suricata-alert.service`     | Optional systemd service to run the email alert script at startup |

📧 Setup: Email Alert Script
Make the script executable:

chmod +x suricata_email_alert.sh
Run it manually for first-time setup:

./suricata_email_alert.sh
The script will ask for your email address on the first run and save it in ~/.suricata_email_config.

Suricata alerts will now be monitored every 5 seconds and sent to your inbox.

Make sure your email server accepts sendmail messages (e.g., for Gmail, you may need an App Password or SMTP relay setup).

📲 Setup: Telegram Alert Script
Configure your bot token and chat ID inside suricata_telegram_alert.py.

Run the script manually:

python3 suricata_telegram_alert.py
It will print alerts to console and send them to your Telegram chat.

⚙️ Optional: Run as a systemd Service (Email Alerts Only)
To have the email alert script run automatically in the background on boot:

Copy the service file to the system directory:

sudo cp suricata-alert.service /etc/systemd/system/


Edit the service file to point to the correct script path:

sudo nano /etc/systemd/system/suricata-alert.service

Replace /path/to/suricata_email_alert.sh with the full absolute path to your script.

Enable and start the service:

sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable suricata-alert.service
sudo systemctl start suricata-alert.service
Check service status:
sudo systemctl status suricata-alert.service


🔄 Notes
The scripts monitor /var/log/suricata/fast.log — make sure Suricata is configured to log alerts there.

If running as a service, ensure the script has proper permissions and log file access.

✅ To-Do
 Add filtering or severity levels

 Rate-limiting to avoid alert spam

 Optionally combine both alert methods into one script
