#ifndef TEA_H
#define TEA_H

#include <stdint.h>
#include <stddef.h>

// TEA constants
#define TEA_BLOCK_SIZE 8  // TEA operates on 64-bit blocks
#define TEA_KEY_SIZE 16   // TEA uses 128-bit keys
#define TEA_DELTA 0x9E3779B9 // Magic constant for TEA
#define TEA_ROUNDS 32     // Number of rounds in TEA

// Function declarations
void tea_encrypt_block(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext);
void tea_decrypt_block(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext);

// CBC mode encryption/decryption
void tea_cbc_encrypt(const uint8_t *plaintext, size_t plaintext_len, 
                     const uint8_t *key, const uint8_t *iv, 
                     uint8_t *ciphertext);
                     
void tea_cbc_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, 
                     const uint8_t *key, const uint8_t *iv, 
                     uint8_t *plaintext);

#endif
