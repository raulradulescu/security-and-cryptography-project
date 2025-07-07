# Security and Cryptography Project

This repository contains implementations of various cryptographic algorithms for educational purposes. The project includes:

- **ECC (Curve25519)**: Elliptic curve cryptography implementation
- **AES**: Advanced Encryption Standard with CBC mode
- **TEA**: Tiny Encryption Algorithm with CBC mode

## Project Structure
    ├── AES/ # AES implementation 
    ├── TEA/ # TEA implementation 
    └── ecc_25519/ # Curve25519 implementation


## Cryptographic Algorithms

### Elliptic Curve Cryptography (Curve25519)

An implementation of the Curve25519 elliptic curve, providing:
- Key pair generation
- Public key derivation
- Shared secret computation
- File encryption and decryption

#### Usage

```bash
# Generate a key pair
cd ecc_25519
make
./keygen mykey

# Encrypt a file
./ecc -e -i plaintext.txt -k mykey.pub -o encrypted.bin

# Decrypt a file
./ecc -d -i encrypted.bin -k mykey.priv -o decrypted.txt
```
### Advanced Encryption Standard (AES)
Implementation of AES with:

- Support for 128, 192, and 256-bit keys
- CBC mode operation
- PKCS#7 padding
#### Usage
```bash
# Compile
cd AES
make

# Encrypt a file
./aes_cbc -e -i plaintext.txt -k key.bin -o encrypted.bin

# Decrypt a file
./aes_cbc -d -i encrypted.bin -k key.bin -o decrypted.txt
```
### Tiny Encryption Algorithm (TEA)
A lightweight block cipher implementation:

- 64-bit block size
- 128-bit key
- CBC mode operation
- PKCS#7 padding

#### Usage
```bash
# Compile
cd TEA
make

# Encrypt a file
./tea_cbc -e -i plaintext.txt -k key.bin -o encrypted.bin

# Decrypt a file
./tea_cbc -d -i encrypted.bin -k key.bin -o decrypted.txt
```

### Building the Project

Prerequisites
- GCC compiler
- Make build system
- Unix-like environment (Linux, macOS, WSL, etc.)

##### Compilation
To build all components:
```bash
# Build ECC implementation
cd ecc_25519
make

# Build AES implementation
cd ../AES
make

# Build TEA implementation
cd ../TEA
make
```

##### Security Considerations
This project is intended for educational purposes only. The implementations provided may not be suitable for production use due to:

- Potential vulnerabilities in the implementation
- Lack of side-channel attack protections
- Limited security auditing

For production use, prefer established cryptographic libraries such as OpenSSL, libsodium, or NaCl.

##### License
This project is open source and available for educational use.

##### Acknowledgments
This project has been made as a homework for the Security and Cryptography course at the West University of Timișoara, Romania. Special thanks to the course instructor, Dr. Darius Galiș for their guidance and support.    
