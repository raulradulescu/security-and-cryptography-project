#ifndef CURVE25519_H
#define CURVE25519_H

#include "common.h"
#include <stdint.h>

// Field size for Curve25519
#define FIELD_SIZE 32  // 256 bits = 32 bytes

// Key types
typedef struct {
    uint8_t private_key[FIELD_SIZE];
    uint8_t public_key[FIELD_SIZE];
} key_pair_t;

// Function declarations
void curve25519_generate_keypair(key_pair_t *keypair);
void curve25519_compute_public(uint8_t *public_key, const uint8_t *private_key);
void curve25519_shared_secret(uint8_t *shared, const uint8_t *private_key, const uint8_t *public_key);
void curve25519_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p);

// Encryption and decryption functions
int ecc_encrypt(const uint8_t *public_key, const uint8_t *plaintext, 
                size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len);
                
int ecc_decrypt(const uint8_t *private_key, const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len);

// Key file handling functions
int read_key(const char *filename, uint8_t *key, crypto_mode_t mode);
void generate_and_save_keypair(const char *filename);

#endif /* CURVE25519_H */