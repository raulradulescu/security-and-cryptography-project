#include "tea.h"
#include <string.h>

// Encrypt a single 64-bit block using TEA
void tea_encrypt_block(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext) {
    uint32_t v0, v1;
    uint32_t k0, k1, k2, k3;
    uint32_t sum = 0;
    
    // Load plaintext into v0, v1
    memcpy(&v0, plaintext, 4);
    memcpy(&v1, plaintext + 4, 4);
    
    // Load key into k0, k1, k2, k3
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    
    // Perform TEA encryption
    for (int i = 0; i < TEA_ROUNDS; i++) {
        sum += TEA_DELTA;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    
    // Store result in ciphertext
    memcpy(ciphertext, &v0, 4);
    memcpy(ciphertext + 4, &v1, 4);
}

// Decrypt a single 64-bit block using TEA
void tea_decrypt_block(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext) {
    uint32_t v0, v1;
    uint32_t k0, k1, k2, k3;
    uint32_t sum = TEA_DELTA * TEA_ROUNDS;
    
    // Load ciphertext into v0, v1
    memcpy(&v0, ciphertext, 4);
    memcpy(&v1, ciphertext + 4, 4);
    
    // Load key into k0, k1, k2, k3
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    
    // Perform TEA decryption
    for (int i = 0; i < TEA_ROUNDS; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= TEA_DELTA;
    }
    
    // Store result in plaintext
    memcpy(plaintext, &v0, 4);
    memcpy(plaintext + 4, &v1, 4);
}

// CBC mode encryption
void tea_cbc_encrypt(const uint8_t *plaintext, size_t plaintext_len, 
                     const uint8_t *key, const uint8_t *iv, 
                     uint8_t *ciphertext) {
    uint8_t block[TEA_BLOCK_SIZE];
    uint8_t prev_block[TEA_BLOCK_SIZE];
    
    // Initialize the previous block with the IV
    memcpy(prev_block, iv, TEA_BLOCK_SIZE);
    
    // CBC encryption processes data in complete blocks
    size_t num_blocks = plaintext_len / TEA_BLOCK_SIZE;
    size_t remaining = plaintext_len % TEA_BLOCK_SIZE;
    
    // Process each complete block
    for (size_t i = 0; i < num_blocks; i++) {
        // XOR plaintext block with previous ciphertext block (or IV for the first block)
        for (size_t j = 0; j < TEA_BLOCK_SIZE; j++) {
            block[j] = plaintext[i * TEA_BLOCK_SIZE + j] ^ prev_block[j];
        }
        
        // Encrypt the XOR result
        tea_encrypt_block(block, key, &ciphertext[i * TEA_BLOCK_SIZE]);
        
        // Save current ciphertext block as previous for next iteration
        memcpy(prev_block, &ciphertext[i * TEA_BLOCK_SIZE], TEA_BLOCK_SIZE);
    }
    
    // Handle the partial last block with PKCS#7 padding if needed
    if (remaining > 0 || plaintext_len == 0) {
        uint8_t padding_value = TEA_BLOCK_SIZE - remaining;
        
        // Copy remaining data
        for (size_t i = 0; i < remaining; i++) {
            block[i] = plaintext[num_blocks * TEA_BLOCK_SIZE + i] ^ prev_block[i];
        }
        
        // Add padding
        for (size_t i = remaining; i < TEA_BLOCK_SIZE; i++) {
            block[i] = padding_value ^ prev_block[i];
        }
        
        // Encrypt the last block
        tea_encrypt_block(block, key, &ciphertext[num_blocks * TEA_BLOCK_SIZE]);
    }
}

// CBC mode decryption
void tea_cbc_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, 
                     const uint8_t *key, const uint8_t *iv, 
                     uint8_t *plaintext) {
    uint8_t block[TEA_BLOCK_SIZE];
    uint8_t prev_block[TEA_BLOCK_SIZE];
    
    // Initialize the previous block with the IV
    memcpy(prev_block, iv, TEA_BLOCK_SIZE);
    
    // Ensure the ciphertext length is a multiple of the block size
    if (ciphertext_len % TEA_BLOCK_SIZE != 0 || ciphertext_len == 0) {
        // This should not happen with proper CBC encryption
        return;
    }
    
    size_t num_blocks = ciphertext_len / TEA_BLOCK_SIZE;
    
    // Process each block
    for (size_t i = 0; i < num_blocks; i++) {
        // Decrypt the current ciphertext block
        tea_decrypt_block(&ciphertext[i * TEA_BLOCK_SIZE], key, block);
        
        // XOR with the previous ciphertext block (or IV for the first block)
        for (size_t j = 0; j < TEA_BLOCK_SIZE; j++) {
            plaintext[i * TEA_BLOCK_SIZE + j] = block[j] ^ prev_block[j];
        }
        
        // Remember current ciphertext block for next iteration
        memcpy(prev_block, &ciphertext[i * TEA_BLOCK_SIZE], TEA_BLOCK_SIZE);
    }
    
    // Handle PKCS#7 padding removal from the last block
    uint8_t padding_value = plaintext[(num_blocks * TEA_BLOCK_SIZE) - 1];
    
    // Validate padding is correct (all padding bytes should be the same value)
    if (padding_value > 0 && padding_value <= TEA_BLOCK_SIZE) {
        for (size_t i = 1; i <= padding_value; i++) {
            if (plaintext[(num_blocks * TEA_BLOCK_SIZE) - i] != padding_value) {
                // Invalid padding, do not remove
                return;
            }
        }
        
        // The padding_value is valid, set it as the number of bytes to remove
        ciphertext_len -= padding_value;
    }
}
