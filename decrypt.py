from cryptography.fernet import Fernet
import os

def verify_password(key):
    """Verify password using password_check.meta before asking for files"""
    meta_file = "password_check.meta"
    if not os.path.exists(meta_file):
        print("[!] Metadata file not found. Cannot verify password.")
        return False
    try:
        with open(meta_file, "rb") as f:
            data = f.read()
        Fernet(key).decrypt(data)
        return True
    except Exception:
        return False

def decrypt_file(input_file, output_file, key):
    cipher = Fernet(key)
    if not os.path.exists(input_file):
        print("[!] Encrypted file not found.")
        return False
    try:
        with open(input_file, "rb") as f:
            data = f.read()
        decrypted_data = cipher.decrypt(data)
        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        print(f"[+] File decrypted successfully: {output_file}")
        return True
    except Exception:
        print("[!] Decryption failed. Wrong password or corrupted file.")
        return False
