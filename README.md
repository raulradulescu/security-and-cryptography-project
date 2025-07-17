# Security and Cryptography Project

This repository contains implementations of various cryptographic algorithms for educational purposes. The project includes:

- **ECC (Curve25519)**: Elliptic curve cryptography implementation
- **AES**: Advanced Encryption Standard with CBC and ECB modes
- **TEA**: Tiny Encryption Algorithm with CBC mode

## Project Structure
```
├── AES/                # AES implementation with CBC/ECB modes
├── TEA/                # TEA implementation with CBC mode
└── ecc_25519/          # Curve25519 implementation
```


## Cryptographic Algorithms

### Elliptic Curve Cryptography (Curve25519)

An implementation of the Curve25519 elliptic curve, providing:
- Cryptographically secure key pair generation
- Public key derivation from private keys
- Elliptic Curve Diffie-Hellman (ECDH) key exchange
- File encryption and decryption using ephemeral keys
- XOR stream cipher with shared secrets

**Features:**
- Based on the reference TweetNaCl implementation for correctness
- Secure random number generation
- Cross-platform compatibility (Windows/Unix)

#### Usage

```bash
# Generate a key pair
cd ecc_25519
make
./keygen mykey

# Encrypt a file
./ecc_main -e -i plaintext.txt -k mykey -o encrypted.bin

# Decrypt a file
./ecc_main -d -i encrypted.bin -k mykey -o decrypted.txt
```

#### Alternative Build Methods
```bash
# Using PowerShell (Windows)
.\build.ps1

# Show testing instructions
.\build.ps1 test
```
### Advanced Encryption Standard (AES)

Implementation of AES with multiple modes and key sizes:

- **Key Sizes**: 128, 192, and 256-bit keys (AES-128/192/256)
- **Modes**: CBC mode (secure) and ECB mode (educational only)
- **Padding**: PKCS#7 padding for arbitrary data lengths
- **Security**: CBC mode uses random IV for cryptographic security

**Security Note**: CBC mode is recommended for real applications, ECB mode is included for educational comparison only.

#### Usage
```bash
# Compile both modes
cd AES
make

# Encrypt with CBC mode (recommended)
./aes_cbc -e -i plaintext.txt -k key.bin -o encrypted.bin

# Decrypt with CBC mode
./aes_cbc -d -i encrypted.bin -k key.bin -o decrypted.txt

# ECB mode (demonstration only)
./aes_ecb -e -i plaintext.txt -k key.bin -o encrypted_ecb.bin
./aes_ecb -d -i encrypted_ecb.bin -k key.bin -o decrypted_ecb.txt
```

#### Alternative Build Methods
```bash
# Using PowerShell (Windows)
.\build.ps1

# Show comprehensive testing guide
.\build.ps1 test
```
### Tiny Encryption Algorithm (TEA)

A lightweight block cipher implementation designed for simplicity and efficiency:

- **Block Size**: 64-bit blocks
- **Key Size**: 128-bit keys (16 bytes)
- **Mode**: CBC mode operation with random IV
- **Padding**: PKCS#7 padding for arbitrary data lengths
- **Rounds**: 32 rounds for security

**Features:**
- Simple and fast encryption/decryption
- Suitable for resource-constrained environments
- Educational implementation of a Feistel cipher

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

#### Alternative Build Methods
```bash
# Using PowerShell (Windows)
.\build.ps1

# Show testing instructions
.\build.ps1 test
```

## Building the Project

### Prerequisites
- **GCC compiler** with C99 support
- **Make build system**
- **Cross-platform**: Works on Windows (with PowerShell), Linux, macOS, WSL

### Build Methods

Each implementation supports multiple build methods:

#### Method 1: Traditional Make
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

#### Method 2: PowerShell Build Scripts (Windows)
```powershell
# Build ECC
cd ecc_25519
.\build.ps1

# Build AES  
cd ..\AES
.\build.ps1

# Build TEA
cd ..\TEA
.\build.ps1
```

#### Method 3: Batch Scripts (Windows)
```cmd
# Available in ECC directory
cd ecc_25519
.\build.bat
```

### Testing

Each implementation includes comprehensive testing instructions:

```bash
# Show testing instructions for any implementation
make test
# or
.\build.ps1 test
```

### Generated Executables

After building, you'll have:

**ECC (ecc_25519/):**
- `ecc_main` - Main encryption/decryption program
- `keygen` - Key pair generation utility

**AES (AES/):**
- `aes_cbc` - AES with CBC mode (recommended)
- `aes_ecb` - AES with ECB mode (educational only)

**TEA (TEA/):**
- `tea_cbc` - TEA with CBC mode

## Security Considerations

This project is intended for educational purposes only. The implementations provided may not be suitable for production use due to:

- **Limited security auditing** - Code has not undergone professional security review
- **Side-channel vulnerabilities** - No protection against timing or power analysis attacks
- **Implementation risks** - Potential bugs or vulnerabilities in custom crypto code
- **Key management** - Simple file-based key storage (not secure for production)

### Cryptographic Security Notes

**ECC Implementation:**
- Uses TweetNaCl reference implementation for mathematical correctness
- Secure against known mathematical attacks on Curve25519
- Random number generation uses system entropy when available

**AES Implementation:**
- Follows FIPS 197 standard specification
- CBC mode provides semantic security with random IVs
- ECB mode is deterministic and should never be used for real data

**TEA Implementation:**
- Simple Feistel cipher design
- Not recommended for new applications (use AES instead)
- Included for educational comparison with modern ciphers

### Production Recommendations

For production use, prefer established and audited cryptographic libraries:
- **OpenSSL** - Comprehensive cryptographic library
- **libsodium** - Modern, easy-to-use crypto library
- **Bouncy Castle** - Cross-platform crypto library

## License

This project is open source and available for educational use.

## Acknowledgments

This project has been developed as coursework for the **Security and Cryptography course** at the **West University of Timișoara, Romania**. 

**Special thanks to:**
- **Dr. Darius Galiș** - Course instructor for guidance and support
- **TweetNaCl team** - For the reference Curve25519 implementation
- **NIST** - For the AES specification and test vectors

## Implementation Details

### Project Evolution
This project demonstrates the evolution from custom cryptographic implementations to integration of proven, reference implementations:

1. **Initial Phase**: Custom ECC implementation with original field arithmetic
3. **Enhancement Phase**: Addition of explicit function names and comprehensive build systems
4. **Documentation Phase**: Complete testing procedures and security considerations

### Key Learning Outcomes
- Understanding of elliptic curve cryptography mathematics
- Importance of using audited reference implementations
- Comparison of symmetric cipher designs (AES vs TEA)
- Practical cryptographic engineering considerations
- Cross-platform build system development    
