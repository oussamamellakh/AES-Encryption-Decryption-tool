# AES Encryption and Decryption Tool

A robust command-line and interactive tool for secure encryption and decryption of text messages and files using the Advanced Encryption Standard (AES).

## Overview

This Python-based encryption tool leverages the AES algorithm through the Fernet implementation to provide secure encryption and decryption capabilities. It's designed for both beginners and advanced users with an intuitive interactive mode and flexible command-line options.

## Features

- **Dual-Mode Operation**: Run in user-friendly interactive mode or via command-line for automation
- **Text & File Support**: Encrypt/decrypt both text messages and files
- **Password-Based Security**: Use memorable passwords that are securely converted to encryption keys
- **Salt Implementation**: Employs cryptographic salt to enhance security
- **PBKDF2 Key Derivation**: Uses PBKDF2 with 100,000 iterations for secure key generation
- **Base64 Output Option**: Get encryption results in readable Base64 format
- **Comprehensive Error Handling**: User-friendly error messages and recovery options
- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux

## How It Works

The tool follows industry-standard encryption practices:

1. **Key Derivation**: Your password is transformed into a secure encryption key using PBKDF2-HMAC-SHA256
- The password is combined with a random salt
- PBKDF2 applies 100,000 iterations of HMAC-SHA256
- This produces a cryptographically strong 256-bit key
  
2. **Salt Generation**: A random salt is generated to prevent dictionary attacks
- Each encryption operation gets a unique salt
- This ensures identical passwords produce different encryption keys
- The salt is stored alongside the encrypted data for decryption
  
3. **AES Encryption**: The Fernet implementation (AES-128 in CBC mode with PKCS7 padding) encrypts your data
- The data is divided into 16-byte (128-bit) blocks
- A random Initialization Vector (IV) is generated
- For the first block:
    - The plaintext block is XORed with the IV
    - The result is encrypted with the AES algorithm
- For subsequent blocks:
    - Each plaintext block is XORed with the previous block's ciphertext
    - The result is encrypted with the AES algorithm
- This chaining mechanism ensures that identical plaintext blocks encrypt differently
- Any change in one block affects all subsequent blocks, enhancing security
  
4. **PKCS7 Padding**: Since AES requires complete blocks
- The final block is padded to reach the full 16-byte size
- PKCS7 padding adds bytes with a value equal to the padding length
- This padding is automatically removed during decryption
  
5. **Message Authentication**: To prevent tampering
- An HMAC-SHA256 is calculated over the ciphertext
- This serves as a cryptographic signature
- During decryption, the HMAC is verified before processing
  
6. **Storage Format**: Encrypted data is stored with its salt to enable later decryption
- The salt length (1 byte) is stored first
- Followed by the salt itself
- Then the complete Fernet-formatted encrypted message
  
7. **Decryption Process**: Reverses the process using the same password and salt
- The salt is extracted from the stored data
- The same PBKDF2 process regenerates the identical key
- The IV is extracted from the Fernet message
- Each ciphertext block is decrypted
- Each decrypted block is XORed with the previous ciphertext block (or IV)
- The padding is removed from the final block
- The HMAC is verified to confirm data integrity

## Security Aspects

- Uses AES encryption (industry standard used by governments and financial institutions)
- Implements key stretching via PBKDF2 to protect against brute-force attacks
- Generates unique salts for each encryption operation
- Does not store passwords
- Provides secure output options (file or Base64)

## Installation

1. Ensure Python 3.6+ is installed on your system
2. Clone this repository:
   ```
   git clone https://github.com/oussamamellakh/AES-Encryption-Decryption-tool.git
   cd AES-Encryption-Decryption-tool
   ```
3. Install required dependencies:
   ```
   pip install cryptography
   ```

## Usage

### Interactive Mode

Simply run the script without any arguments for a guided experience:

```
python aes_encryption_tool.py
```

You'll see a menu with four options:
1. Encrypt a message
2. Decrypt a message
3. Encrypt a file
4. Decrypt a file

Follow the prompts to complete your desired operation.

### Command-Line Interface

For advanced usage and automation, use the command-line interface:

```
python aes_encryption_tool.py [-h] (-e | -d) [-i INPUT] [-o OUTPUT] [-p PASSWORD] [-t]
```

Arguments:
- `-e, --encrypt`: Encrypt mode
- `-d, --decrypt`: Decrypt mode
- `-i, --input`: Input file or message
- `-o, --output`: Output file (optional)
- `-p, --password`: Password for encryption/decryption
- `-t, --text`: Use text mode instead of file mode
- `-h, --help`: Show help message

### Examples

**Encrypt a text message:**
```
python aes_encryption_tool.py -e -t -p "your_secure_password" -i "This is a secret message"
```

**Decrypt a text message:**
```
python aes_encryption_tool.py -d -t -p "your_secure_password"
```
(You'll be prompted to enter the encrypted text and salt)

**Encrypt a file:**
```
python aes_encryption_tool.py -e -i important_document.pdf -o encrypted_document.enc -p "your_secure_password"
```

**Decrypt a file:**
```
python aes_encryption_tool.py -d -i encrypted_document.enc -o decrypted_document.pdf -p "your_secure_password"
```

## Understanding the Output

When encrypting, the tool provides:
1. The encrypted data (in Base64 format for text mode)
2. The salt (in Base64 format for text mode)

**Important**: For successful decryption, you need:
- The encrypted data
- The salt
- The original password

## Use Cases

- Secure storage of sensitive text notes
- Protecting confidential documents
- Encrypting configuration files with sensitive information
- Secure communication via encrypted message exchange
- Protecting backup files

## Technical Details

- **Encryption Algorithm**: AES-128 in CBC mode with PKCS7 padding
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt Size**: 16 bytes (128 bits)
- **Output Format**: Binary file structure or Base64 text
- **Libraries Used**: cryptography (Python)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

*Disclaimer: This tool is provided for legitimate security purposes. Always use encryption responsibly and in compliance with all applicable laws and regulations.*
