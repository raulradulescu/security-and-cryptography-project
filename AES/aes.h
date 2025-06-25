/****************  aes.h  ****************/
#ifndef AES_H
#define AES_H
#include <stdint.h>
#include <stddef.h>
#include "common.h"
#define AES_BLOCK_SIZE 16

/* Expanded key – enough room for AES‑256 (14 rounds + 1) */
typedef struct {
    uint32_t rk[60];   // round keys
    int       Nr;      // number of rounds: 10 / 12 / 14
} aes_key_t;

/* key_bits must be 128, 192 or 256 */
void aes_key_setup(aes_key_t *ks, const uint8_t *key, size_t key_bits);

/* One 16‑byte block ECB encryption/decryption */
void aes_encrypt_block(const aes_key_t *ks, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(const aes_key_t *ks, const uint8_t in[16], uint8_t out[16]);

#endif /* AES_H */