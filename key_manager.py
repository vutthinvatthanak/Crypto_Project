from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"

def generate_key():
    """Generate a new AES key using Fernet and save it."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    """Load the saved AES key or generate a new one if not exists."""
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    return key
