#!/usr/bin/env python3
import time
import requests

log_file = "/var/log/suricata/fast.log"
bot_token = "8109660764:AAGVspEGYmQ67ANbkxUKOUJPbrvhXF2aw4k"
chat_id = "1775583708"

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {"chat_id": chat_id, "text": message}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"Telegram Error: {e}")

last_line = ""

print("[*] Monitoring Suricata alerts...")

while True:
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
            if lines:
                if lines[-1] != last_line:
                    last_line = lines[-1]
                    alert_msg = f"[SURICATA ALERT]\n{last_line.strip()}"
                    print(alert_msg)
                    send_telegram_alert(alert_msg)
        time.sleep(5)
    except KeyboardInterrupt:
        print("Exiting...")
        break
    except Exception as e:
        print(f"Error: {e}")
        time.sleep(5)
