# users.py
from werkzeug.security import generate_password_hash, check_password_hash

users = {
    "Jakleen": generate_password_hash("MikroTik@2025"),
    "Mahmoud": generate_password_hash("SecurePass123"),
    "Taga": generate_password_hash("Network!"),
    "Mo'men": generate_password_hash("4444mikrotik")
}
