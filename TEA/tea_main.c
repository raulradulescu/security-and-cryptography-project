#include "tea.h"
#include "common.h"
#include <time.h>

int main(int argc, char **argv) {
    cli_args_t args = {0};
    parse_cli(argc, argv, &args);
    
    // Read input file
    size_t input_len;
    uint8_t *input = read_file(args.in_fname, &input_len);
    
    // Read key file
    size_t key_len;
    uint8_t *key_data = read_file(args.key_fname, &key_len);
    
    // Key must be 16 bytes (128 bits) for TEA
    if (key_len < TEA_KEY_SIZE) {
        fprintf(stderr, "Error: Key must be at least %d bytes for TEA\n", TEA_KEY_SIZE);
        free(input);
        free(key_data);
        return EXIT_FAILURE;
    }
    
    if (args.mode == MODE_ENCRYPT) {
        // For CBC encryption, we need:
        // 1. An initialization vector (IV)
        // 2. Padding to ensure the plaintext is a multiple of the block size
        uint8_t iv[TEA_BLOCK_SIZE] = {0};
        
        // Generate a random IV
        // In a real implementation, you would want to use a secure RNG
        time_t now = time(NULL);
        memcpy(iv, &now, sizeof(time_t));
        
        // Calculate output size: IV + plaintext + potential padding (up to one block)
        size_t output_len = TEA_BLOCK_SIZE + // IV
                           ((input_len / TEA_BLOCK_SIZE) + 1) * TEA_BLOCK_SIZE; // padded data
        
        uint8_t *output = malloc(output_len);
        if (!output) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        // Store the IV at the beginning of the output
        memcpy(output, iv, TEA_BLOCK_SIZE);
        
        // Encrypt the plaintext using CBC mode
        tea_cbc_encrypt(input, input_len, key_data, iv, output + TEA_BLOCK_SIZE);
        
        // Calculate the actual output length after encryption (IV + padded ciphertext)
        output_len = TEA_BLOCK_SIZE + // IV
                     ((input_len / TEA_BLOCK_SIZE) + 1) * TEA_BLOCK_SIZE; // padded data
        
        // Write output (IV + ciphertext)
        write_file(args.out_fname, output, output_len);
        
        // Clean up
        free(output);
        
    } else { // MODE_DECRYPT
        if (input_len < TEA_BLOCK_SIZE || input_len % TEA_BLOCK_SIZE != 0) {
            fprintf(stderr, "Error: Invalid ciphertext size for TEA CBC mode\n");
            free(input);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        // Extract IV from the beginning of the ciphertext
        uint8_t iv[TEA_BLOCK_SIZE];
        memcpy(iv, input, TEA_BLOCK_SIZE);
        
        // Calculate output size: ciphertext without IV
        size_t output_len = input_len - TEA_BLOCK_SIZE;
        
        uint8_t *output = malloc(output_len);
        if (!output) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        // Decrypt the ciphertext using CBC mode
        tea_cbc_decrypt(input + TEA_BLOCK_SIZE, output_len, key_data, iv, output);
        
        // Determine the actual plaintext length by examining the padding
        // The last byte indicates the padding size (PKCS#7)
        uint8_t padding = output[output_len - 1];
        if (padding > 0 && padding <= TEA_BLOCK_SIZE) {
            // Verify the padding is correct
            int valid_padding = 1;
            for (size_t i = 1; i <= padding; i++) {
                if (output[output_len - i] != padding) {
                    valid_padding = 0;
                    break;
                }
            }
            
            if (valid_padding) {
                output_len -= padding;
            }
        }
        
        // Write the decrypted plaintext
        write_file(args.out_fname, output, output_len);
        
        // Clean up
        free(output);
    }
    
    // Common cleanup
    free(input);
    free(key_data);
    
    return EXIT_SUCCESS;
}
