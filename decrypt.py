from cryptography.fernet import Fernet

def decrypt_file(input_file, output_file, key):
    """Decrypt the contents of an encrypted file."""
    cipher = Fernet(key)

    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception as e:
        print("[!] Decryption failed. Wrong key or corrupt file.")
        return

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] File decrypted successfully: {output_file}")
