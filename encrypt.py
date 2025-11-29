from cryptography.fernet import Fernet

def encrypt_file(input_file, output_file, key):
    """Encrypt the contents of a file."""
    cipher = Fernet(key)

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted_data = cipher.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(encrypted_data)

    print(f"[+] File encrypted successfully: {output_file}")
