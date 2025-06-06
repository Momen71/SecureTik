import requests
import argparse

def send_telegram_message(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    response = requests.post(url, data=payload)
    print(response.json())

def main():
    parser = argparse.ArgumentParser(description='Send fail2ban alert to Telegram.')
    parser.add_argument('--ip', required=True, help='IP address involved')
    parser.add_argument('--type', required=True, help='Type of action (ban/unban)')

    args = parser.parse_args()

    bot_token = "7785312104:AAGxfN_eBbqGb68XlbAHx3wCeiswb8T76bM"
    chat_id = "1360112999"

    if args.type == "ban":
        message = f"🚨 Alert! IP {args.ip} has been banned."


    elif args.type == "unban":
        message = f"ℹ️ Info: IP {args.ip} has been unbanned."
    else:
        message = f"Info: Action {args.type} for IP {args.ip}"

    send_telegram_message(bot_token, chat_id, message)

if __name__ == "__main__":
    main()
