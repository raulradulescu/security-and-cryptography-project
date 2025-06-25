#include "common.h"
#include "curve25519.h"

int main(int argc, char **argv) {
    cli_args_t args = {0};
    parse_cli(argc, argv, &args);
    
    if (args.mode == MODE_ENCRYPT) {
        // Reading the public key for encryption
        uint8_t public_key[FIELD_SIZE];
        if (!read_key(args.key_fname, public_key, MODE_ENCRYPT)) {
            fprintf(stderr, "Failed to read valid public key\n");
            return EXIT_FAILURE;
        }
        
        // Reading the input file
        size_t plaintext_len;
        uint8_t *plaintext = read_file(args.in_fname, &plaintext_len);
        
        // Encrypting the input
        uint8_t *ciphertext;
        size_t ciphertext_len;
        
        if (!ecc_encrypt(public_key, plaintext, plaintext_len, &ciphertext, &ciphertext_len)) {
            fprintf(stderr, "Encryption failed\n");
            free(plaintext);
            return EXIT_FAILURE;
        }
        
        // Writing the output file
        write_file(args.out_fname, ciphertext, ciphertext_len);
        
        // Cleanup
        free(plaintext);
        free(ciphertext);
        
        printf("File encrypted successfully\n");
    } else { // MODE_DECRYPT
        // Reading the private key for decryption
        uint8_t private_key[FIELD_SIZE];
        if (!read_key(args.key_fname, private_key, MODE_DECRYPT)) {
            fprintf(stderr, "Failed to read valid private key\n");
            return EXIT_FAILURE;
        }
        
        // Reading the encrypted file
        size_t ciphertext_len;
        uint8_t *ciphertext = read_file(args.in_fname, &ciphertext_len);
        
        // Decrypting the input
        uint8_t *plaintext;
        size_t plaintext_len;
        
        if (!ecc_decrypt(private_key, ciphertext, ciphertext_len, &plaintext, &plaintext_len)) {
            fprintf(stderr, "Decryption failed\n");
            free(ciphertext);
            return EXIT_FAILURE;
        }
        
        // Writing the output file
        write_file(args.out_fname, plaintext, plaintext_len);
        
        // Cleanup
        free(ciphertext);
        free(plaintext);
        
        printf("File decrypted successfully\n");
    }
    
    return EXIT_SUCCESS;
}