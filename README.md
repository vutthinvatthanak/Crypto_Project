# Crypto_Project
Overview

This is a Python-based secure file encryption and decryption tool that uses AES encryption with Fernet from the cryptography library. The tool ensures that files are protected with a strong password, and password verification is enforced before decryption.

Key features include:

Strong password enforcement

File encryption and decryption

Password verification using metadata (password_check.meta)

Salted key derivation with PBKDF2HMAC

User-friendly command-line menu

Project Structure
decrypt.py           # Handles decryption and password verification
encrypt.py           # Handles encryption and metadata creation
key_manager.py       # Main logic: password input, key derivation, file crypto, CLI menu
main.py              # Optional: helper to run the App class
strong_password.py   # Password strength checker
password_check.meta  # Metadata file for password verification
salt.bin             # Salt file used for key derivation
secret.key           # Optional key storage

Requirements

Python 3.13.9

Libraries:

cryptography


Install dependencies with:

pip install cryptography

Usage

Run the application

python key_manager.py

or

python main.py


Set a strong password
Requirements:

Minimum 8 characters

At least 1 uppercase letter

At least 1 lowercase letter

At least 1 number

At least 1 special character (!@#$%^&*(),.?":{}|<>)

Menu Options

Encrypt a file:
Enter the path of the file to encrypt and provide an output filename.

Decrypt a file:
Enter the password, encrypted file path, and the output filename for the decrypted file.

Exit: Quit the program

Password Verification

The program uses password_check.meta to verify that the password is correct before decryption.

Example Workflow
=======================================
🔒 SECURE FILE ENCRYPTION TOOL 🔒
=======================================

Enter a strong password: ********

==============================
      MENU OPTIONS
==============================
1. Encrypt a file
2. Decrypt a file
3. Exit

Choose an option: 1
Enter file to encrypt: secret.txt
Enter output encrypted file: secret.enc
[+] File encrypted successfully: secret.enc

Choose an option: 2
Enter password to decrypt: ********
Enter encrypted file path: secret.enc
Enter decrypted output file: secret_decrypted.txt
[+] File decrypted successfully: secret_decrypted.txt

Notes

Ensure salt.bin and password_check.meta are kept safe; losing them may make decryption impossible.

If password_check.meta is missing, decryption cannot verify the password.

Encryption overwrites password_check.meta with every new encryption, so do not delete it if you plan to decrypt files later.

Security

Uses Fernet symmetric encryption (AES-128 in CBC mode with HMAC verification)

Uses PBKDF2HMAC for deriving a secure key from your password

Ensures strong password enforcement before encrypting files
