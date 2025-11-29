from key_manager import load_key
from encrypt import encrypt_file
from decrypt import decrypt_file

def main():
    print("=======================================")
    print("     AES FILE ENCRYPTION TOOL")
    print("=======================================")

    key = load_key()   # Load or auto-generate

    while True:
        print("\nMENU:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            input_file = input("Enter file path to encrypt: ")
            output_file = input("Enter output encrypted filename (e.g., file.enc): ")
            encrypt_file(input_file, output_file, key)

        elif choice == "2":
            input_file = input("Enter encrypted file path: ")
            output_file = input("Enter output decrypted filename (e.g., output.txt): ")
            decrypt_file(input_file, output_file, key)

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
