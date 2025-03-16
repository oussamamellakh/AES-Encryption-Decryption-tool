from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argparse
import sys

def generate_key_from_password(password, salt=None):
    """Generate a Fernet key from a password and optional salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt if not provided
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode()
    
    # Use PBKDF2 to derive a secure key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    
    return key, salt

def encrypt_message(message, password, salt=None):
    """Encrypt a message using a password."""
    # Generate a key from the password
    key, salt = generate_key_from_password(password, salt)
    
    # Create a Fernet cipher with the key
    cipher = Fernet(key)
    
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode()
    
    # Encrypt the message
    encrypted_message = cipher.encrypt(message)
    
    return encrypted_message, salt

def decrypt_message(encrypted_message, password, salt):
    """Decrypt a message using a password and salt."""
    # Generate the same key from the password and salt
    key, _ = generate_key_from_password(password, salt)
    
    # Create a Fernet cipher with the key
    cipher = Fernet(key)
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message)
    
    return decrypted_message

def save_encrypted_data(encrypted_message, salt, output_file):
    """Save encrypted message and salt to a file."""
    with open(output_file, 'wb') as f:
        # Write the salt length (1 byte, max 255)
        f.write(len(salt).to_bytes(1, byteorder='big'))
        # Write the salt
        f.write(salt)
        # Write the encrypted message
        f.write(encrypted_message)

def load_encrypted_data(input_file):
    """Load encrypted message and salt from a file."""
    with open(input_file, 'rb') as f:
        # Read the salt length
        salt_length = int.from_bytes(f.read(1), byteorder='big')
        # Read the salt
        salt = f.read(salt_length)
        # Read the encrypted message
        encrypted_message = f.read()
    
    return encrypted_message, salt

def interactive_mode():
    """Run in interactive mode when no command line arguments are provided."""
    print("=== AES Encryption/Decryption Tool ===")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Encrypt a file")
    print("4. Decrypt a file")
    
    choice = input("\nSelect an option (1-4): ")
    
    try:
        if choice == "1":  # Encrypt a message
            message = input("Enter message to encrypt: ")
            password = input("Enter encryption password: ")
            
            encrypted_data, salt = encrypt_message(message, password)
            
            print("\nResult:")
            print("Encrypted message (base64):", base64.b64encode(encrypted_data).decode())
            print("Salt (base64):", base64.b64encode(salt).decode())
            print("\nKeep both the encrypted message and salt to decrypt later!")
            
            save_option = input("\nSave to file? (y/n): ").lower()
            if save_option.startswith('y'):
                output_file = input("Enter output filename: ")
                save_encrypted_data(encrypted_data, salt, output_file)
                print(f"Encrypted message saved to {output_file}")
        
        elif choice == "2":  # Decrypt a message
            encrypted_input = input("Enter encrypted message (base64): ")
            encrypted_data = base64.b64decode(encrypted_input)
            salt_input = input("Enter salt (base64): ")
            salt = base64.b64decode(salt_input)
            password = input("Enter decryption password: ")
            
            try:
                decrypted_data = decrypt_message(encrypted_data, password, salt)
                print("\nResult:")
                print("Decrypted message:", decrypted_data.decode())
                
                save_option = input("\nSave to file? (y/n): ").lower()
                if save_option.startswith('y'):
                    output_file = input("Enter output filename: ")
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Decrypted message saved to {output_file}")
            except Exception as e:
                print(f"Decryption failed: {str(e)}")
        
        elif choice == "3":  # Encrypt a file
            input_file = input("Enter file to encrypt: ")
            password = input("Enter encryption password: ")
            output_file = input("Enter output filename (default: [input].enc): ")
            if not output_file:
                output_file = input_file + ".enc"
            
            try:
                with open(input_file, 'rb') as f:
                    data = f.read()
                
                encrypted_data, salt = encrypt_message(data, password)
                save_encrypted_data(encrypted_data, salt, output_file)
                print(f"File encrypted and saved to {output_file}")
            except Exception as e:
                print(f"Encryption failed: {str(e)}")
        
        elif choice == "4":  # Decrypt a file
            input_file = input("Enter encrypted file: ")
            password = input("Enter decryption password: ")
            output_file = input("Enter output filename (default: [input].dec): ")
            if not output_file:
                output_file = input_file.rsplit('.enc', 1)[0] + ".dec"
            
            try:
                encrypted_data, salt = load_encrypted_data(input_file)
                decrypted_data = decrypt_message(encrypted_data, password, salt)
                
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                print(f"File decrypted and saved to {output_file}")
            except Exception as e:
                print(f"Decryption failed: {str(e)}")
        
        else:
            print("Invalid option selected.")
    
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    # Check if any arguments were provided
    if len(sys.argv) == 1:
        # No arguments provided, run in interactive mode
        interactive_mode()
        return
    
    # If arguments were provided, use argparse as before
    parser = argparse.ArgumentParser(description='Encrypt or decrypt data using AES.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt mode')
    group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt mode')
    
    parser.add_argument('-i', '--input', help='Input file (for file mode) or message (for text mode)')
    parser.add_argument('-o', '--output', help='Output file (optional)')
    parser.add_argument('-p', '--password', help='Password for encryption/decryption')
    parser.add_argument('-t', '--text', action='store_true', help='Use text mode instead of file mode')
    
    args = parser.parse_args()
    
    try:
        if args.encrypt:
            if args.text:
                if not args.input:
                    args.input = input("Enter message to encrypt: ")
                if not args.password:
                    args.password = input("Enter encryption password: ")
                
                encrypted_data, salt = encrypt_message(args.input, args.password)
                
                if args.output:
                    save_encrypted_data(encrypted_data, salt, args.output)
                    print(f"Encrypted message saved to {args.output}")
                else:
                    print("Encrypted message (base64):", base64.b64encode(encrypted_data).decode())
                    print("Salt (base64):", base64.b64encode(salt).decode())
                    print("Keep this salt to decrypt your message later!")
            else:
                if not args.input:
                    args.input = input("Enter input file path: ")
                if not args.password:
                    args.password = input("Enter encryption password: ")
                if not args.output:
                    args.output = args.input + ".enc"
                
                with open(args.input, 'rb') as f:
                    data = f.read()
                
                encrypted_data, salt = encrypt_message(data, args.password)
                save_encrypted_data(encrypted_data, salt, args.output)
                print(f"File encrypted and saved to {args.output}")
        
        elif args.decrypt:
            if args.text:
                if not args.input:
                    args.input = input("Enter encrypted message (base64): ")
                    encrypted_data = base64.b64decode(args.input)
                    salt_base64 = input("Enter salt (base64): ")
                    salt = base64.b64decode(salt_base64)
                else:
                    # Assuming input contains both encrypted data and salt
                    encrypted_data, salt = None, None
                    print("For text mode with direct input, use interactive mode (no -i flag)")
                    return
                
                if not args.password:
                    args.password = input("Enter decryption password: ")
                
                decrypted_data = decrypt_message(encrypted_data, args.password, salt)
                
                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Decrypted message saved to {args.output}")
                else:
                    try:
                        print("Decrypted message:", decrypted_data.decode())
                    except UnicodeDecodeError:
                        print("Decrypted data is not text. Use -o to save to a file.")
            else:
                if not args.input:
                    args.input = input("Enter encrypted file path: ")
                if not args.password:
                    args.password = input("Enter decryption password: ")
                if not args.output:
                    args.output = args.input.rsplit('.enc', 1)[0] + ".dec"
                
                encrypted_data, salt = load_encrypted_data(args.input)
                decrypted_data = decrypt_message(encrypted_data, args.password, salt)
                
                with open(args.output, 'wb') as f:
                    f.write(decrypted_data)
                print(f"File decrypted and saved to {args.output}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
