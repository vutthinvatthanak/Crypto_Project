from cryptography.fernet import Fernet

def encrypt_file(input_file, output_file, key):
    """Encrypt the contents of a file using the provided key."""

    cipher = Fernet(key)

    # Read input file
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[!] Error: File '{input_file}' not found.")
        return
    except PermissionError:
        print(f"[!] Permission denied when opening '{input_file}'.")
        return

    # Encrypt data
    encrypted_data = cipher.encrypt(data)

    # Save encrypted file
    try:
        with open(output_file, "wb") as f:
            f.write(encrypted_data)
    except PermissionError:
        print(f"[!] Permission denied when writing to '{output_file}'.")
        return

    print(f"[+] File encrypted successfully: {output_file}")
