import os
import sys
import getpass
import re
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_FILE = "salt.bin"
META_FILE = "password_check.meta"

# ===== Helper Functions =====
def print_success(msg):
    print(f"\033[92m[+] {msg}\033[0m")

def print_error(msg):
    print(f"\033[91m[!] {msg}\033[0m")

def print_warning(msg):
    print(f"\033[93m[!] {msg}\033[0m")

# ===== Password Strength Checker =====
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Strong password"

# ===== Key Manager =====
def load_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

def derive_key(password: str):
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ===== Core File Crypto Manager =====
class FileCryptoManager:
    def __init__(self, key):
        self.key = key
        self.cipher = Fernet(self.key)

    def verify_password(self):
        if not os.path.exists(META_FILE):
            print_error("Metadata file not found. Cannot verify password.")
            return False
        try:
            with open(META_FILE, "rb") as f:
                data = f.read()
            self.cipher.decrypt(data)
            return True
        except Exception:
            return False

    def encrypt_file(self, input_file, output_file):
        if not os.path.exists(input_file):
            print_error("Input file not found.")
            return False
        try:
            with open(input_file, "rb") as f:
                data = f.read()
            encrypted_data = self.cipher.encrypt(data)
            with open(output_file, "wb") as f:
                f.write(encrypted_data)
            # Update metadata
            with open(META_FILE, "wb") as f:
                f.write(self.cipher.encrypt(b"verify_password"))
            return True
        except Exception:
            return False

    def decrypt_file(self, input_file, output_file):
        if not os.path.exists(input_file):
            print_error("Encrypted file not found.")
            return False
        try:
            with open(input_file, "rb") as f:
                data = f.read()
            decrypted_data = self.cipher.decrypt(data)
            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            return True
        except Exception:
            print_error("Decryption failed. Wrong password or corrupted file.")
            return False

# ===== Main Application =====
class App:
    def __init__(self):
        print("="*55)
        print("\033[96m\033[1m        🔒 SECURE FILE ENCRYPTION TOOL 🔒        \033[0m")
        print("="*55)
        self.key = self.ask_password()
        self.manager = FileCryptoManager(self.key)

    def ask_password(self):
        while True:
            password = getpass.getpass("Enter a strong password: ")
            valid, msg = is_strong_password(password)
            if valid:
                print_success("Password accepted!")
                return derive_key(password)
            else:
                print_warning(msg)

    def run(self):
        while True:
            print("\n" + "="*55)
            print("\033[94m\033[1m                  MENU OPTIONS                  \033[0m")
            print("="*55)
            print("1. Encrypt a file")
            print("2. Decrypt a file")
            print("3. Exit")
            print("="*55)
            choice = input("Choose an option: ").strip()

            if choice == "1":
                self.encrypt_action()
            elif choice == "2":
                self.decrypt_action()
            elif choice == "3":
                print("\033[96mGoodbye! 👋\033[0m")
                sys.exit(0)
            else:
                print_warning("Invalid choice. Please enter 1, 2, or 3.")

    def encrypt_action(self):
        input_file = input("Enter file to encrypt: ").strip()
        output_file = input("Enter output encrypted file: ").strip()
        if self.manager.encrypt_file(input_file, output_file):
            print_success(f"File encrypted successfully: {output_file}")
        else:
            print_error("Encryption failed!")

    def decrypt_action(self):
        password_check = getpass.getpass("Enter password to decrypt: ").strip()
        key_check = derive_key(password_check)
        temp_manager = FileCryptoManager(key_check)
        if not temp_manager.verify_password():
            print_error("Wrong password. Program terminated!")
            sys.exit(1)
        input_file = input("Enter encrypted file path: ").strip()
        output_file = input("Enter decrypted output file: ").strip()
        if temp_manager.decrypt_file(input_file, output_file):
            print_success(f"File decrypted successfully: {output_file}")
        else:
            print_error("Decryption failed!")

# ===== Entry Point =====
if __name__ == "__main__":
    app = App()
    app.run()
