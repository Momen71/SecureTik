import requests

def send_telegram_message(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    response = requests.post(url, data=payload)
    print(response.json())

if __name__ == "__main__":
    bot_token = "7785312104:AAGxfN_eBbqGb68XlbAHx3wCeiswb8T76bM"
    chat_id = "1360112999"
    message = "Salam! This is a test message from SecureTikBot"

    send_telegram_message(bot_token, chat_id, message)
