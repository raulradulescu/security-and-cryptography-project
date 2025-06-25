// aes_main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> // For bool type
#include <fcntl.h>   // For O_RDONLY
#include <unistd.h>  // For read(), close() - for /dev/urandom

#include "common.h"
#include "aes.h" // Include the Tiny AES header

#define AES_BLOCKLEN 16 // AES block size in bytes
#define IV_LEN AES_BLOCKLEN // IV size is same as block size

// --- Padding Functions (PKCS#7) ---

// Adds PKCS#7 padding to a buffer.
// Returns a new buffer with padding, updates *padded_len.
// The caller must free the returned buffer.
uint8_t* pkcs7_pad(const uint8_t* data, size_t data_len, size_t* padded_len) {
    size_t padding_len = AES_BLOCKLEN - (data_len % AES_BLOCKLEN);
    *padded_len = data_len + padding_len;
    uint8_t* padded_data = malloc(*padded_len);
    if (!padded_data) {
        perror("Failed to allocate memory for padding");
        return NULL;
    }

    memcpy(padded_data, data, data_len);
    memset(padded_data + data_len, (uint8_t)padding_len, padding_len);

    return padded_data;
}

// Removes PKCS#7 padding from a buffer.
// Returns true on success, updates *data_len to the original length.
// Returns false if padding is invalid.
bool pkcs7_unpad(const uint8_t* padded_data, size_t padded_len, size_t* data_len) {
    if (padded_len == 0 || padded_len % AES_BLOCKLEN != 0) {
        fprintf(stderr, "Error: Invalid padded data length.\n");
        return false;
    }

    uint8_t padding_len = padded_data[padded_len - 1];

    // Check if padding length is valid
    if (padding_len == 0 || padding_len > AES_BLOCKLEN) {
        fprintf(stderr, "Error: Invalid padding value.\n");
        return false;
    }

    // Verify that all padding bytes have the correct value
    for (size_t i = 0; i < padding_len; ++i) {
        if (padded_data[padded_len - 1 - i] != padding_len) {
            fprintf(stderr, "Error: Invalid padding bytes detected.\n");
            return false;
        }
    }

    *data_len = padded_len - padding_len;
    return true;
}

// --- IV Generation ---

// Generates a random IV.
// Returns true on success, false on failure.
bool generate_iv(uint8_t iv[IV_LEN]) {
    // Use /dev/urandom for better randomness on Unix-like systems
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Error opening /dev/urandom. Using insecure fallback (rand)");
        // Insecure fallback - DO NOT USE IN PRODUCTION
        srand((unsigned int)time(NULL)); // Seed only once if using rand()
        for (int i = 0; i < IV_LEN; ++i) {
            iv[i] = rand() % 256;
        }
        return true; // Indicate success even with fallback for demo purposes
    }

    ssize_t bytes_read = read(fd, iv, IV_LEN);
    close(fd);

    if (bytes_read != IV_LEN) {
        fprintf(stderr, "Error reading from /dev/urandom.\n");
        return false;
    }
    return true;
}


// --- Main AES Logic ---

int main(int argc, char **argv) {
    cli_args_t args = {0}; // Initialize struct
    parse_cli(argc, argv, &args);

    // 1. Read Key
    size_t key_len;
    uint8_t *key_buf = read_file(args.key_fname, &key_len);
    if (!key_buf) {
        return EXIT_FAILURE; // read_file prints error
    }

    // Validate Key Size
    int key_bits;
    if (key_len == 16) {
        key_bits = 128;
    } else if (key_len == 24) {
        key_bits = 192;
    } else if (key_len == 32) {
        key_bits = 256;
    } else {
        fprintf(stderr, "Error: Invalid key size (%zu bytes). Must be 16, 24, or 32 bytes.\n", key_len);
        free(key_buf);
        return EXIT_FAILURE;
    }
    printf("Using AES-%d\n", key_bits);

    // --- Initialize AES Context ---
    // TinyAES determines key size from the key buffer itself during init.
    struct AES_ctx ctx;

    // Buffers for data
    uint8_t *in_buf = NULL;
    size_t in_len = 0;
    uint8_t *out_buf = NULL;
    size_t out_len = 0;
    uint8_t iv[IV_LEN];


    // --- Mode-Specific Operations ---
    if (args.mode == MODE_ENCRYPT) {
        printf("Mode: Encrypt\n");

        // 2. Read Input Plaintext
        in_buf = read_file(args.in_fname, &in_len);
        if (!in_buf) {
            free(key_buf);
            return EXIT_FAILURE;
        }
        printf("Read %zu bytes of plaintext from %s\n", in_len, args.in_fname);

        // 3. Generate IV
        if (!generate_iv(iv)) {
            free(key_buf);
            free(in_buf);
            return EXIT_FAILURE;
        }
        printf("Generated random IV.\n");

        // 4. Pad Plaintext
        size_t padded_len;
        uint8_t *padded_buf = pkcs7_pad(in_buf, in_len, &padded_len);
        if (!padded_buf) {
            free(key_buf);
            free(in_buf);
            return EXIT_FAILURE;
        }
        printf("Padded plaintext to %zu bytes.\n", padded_len);
        free(in_buf); // Don't need original plaintext buffer anymore
        in_buf = padded_buf; // Use padded buffer for encryption
        in_len = padded_len; // Update length

        // 5. Initialize AES for CBC Encryption
        AES_init_ctx_iv(&ctx, key_buf, iv);

        // 6. Encrypt Data (TinyAES CBC encrypts in-place)
        out_buf = malloc(in_len); // Output ciphertext has same length as padded plaintext
        if (!out_buf) {
            perror("Failed to allocate memory for output buffer");
            free(key_buf);
            free(in_buf);
            return EXIT_FAILURE;
        }
        memcpy(out_buf, in_buf, in_len); // Copy plaintext to output buffer
        AES_CBC_encrypt_buffer(&ctx, out_buf, in_len);
        out_len = in_len;
        printf("Encryption complete.\n");


        // 7. Write IV + Ciphertext to Output File
        FILE *f_out = fopen(args.out_fname, "wb");
        if (!f_out) {
            perror(args.out_fname);
            free(key_buf);
            free(in_buf); // which is padded_buf
            free(out_buf);
            return EXIT_FAILURE;
        }
        // Write IV first
        if (fwrite(iv, 1, IV_LEN, f_out) != IV_LEN) {
             fprintf(stderr, "Error writing IV to %s\n", args.out_fname);
             fclose(f_out);
             free(key_buf);
             free(in_buf);
             free(out_buf);
             return EXIT_FAILURE;
        }
        // Write Ciphertext
        if (fwrite(out_buf, 1, out_len, f_out) != out_len) {
             fprintf(stderr, "Error writing ciphertext to %s\n", args.out_fname);
             fclose(f_out);
             free(key_buf);
             free(in_buf);
             free(out_buf);
             return EXIT_FAILURE;
        }
        fclose(f_out);
        printf("Written IV (%d bytes) and Ciphertext (%zu bytes) to %s\n", IV_LEN, out_len, args.out_fname);


    } else { // MODE_DECRYPT
        printf("Mode: Decrypt\n");

        // 2. Read Input Ciphertext (which includes IV)
        in_buf = read_file(args.in_fname, &in_len);
         if (!in_buf) {
            free(key_buf);
            return EXIT_FAILURE;
        }

        // 3. Extract IV and Ciphertext Data
        if (in_len < IV_LEN) {
            fprintf(stderr, "Error: Input file %s is too short to contain an IV.\n", args.in_fname);
            free(key_buf);
            free(in_buf);
            return EXIT_FAILURE;
        }
        memcpy(iv, in_buf, IV_LEN); // Copy IV from the beginning
        size_t ciphertext_len = in_len - IV_LEN;
        printf("Read IV (%d bytes) and Ciphertext (%zu bytes) from %s\n", IV_LEN, ciphertext_len, args.in_fname);


        // Check if ciphertext length is valid (must be multiple of block size)
        if (ciphertext_len == 0 || ciphertext_len % AES_BLOCKLEN != 0) {
             fprintf(stderr, "Error: Ciphertext length (%zu bytes) is not a multiple of %d.\n", ciphertext_len, AES_BLOCKLEN);
             free(key_buf);
             free(in_buf);
             return EXIT_FAILURE;
        }


        // 4. Initialize AES for CBC Decryption
        AES_init_ctx_iv(&ctx, key_buf, iv);


        // 5. Decrypt Data (TinyAES CBC decrypts in-place)
        // Create a buffer for the actual ciphertext data (without IV)
        uint8_t *ciphertext_buf = malloc(ciphertext_len);
         if (!ciphertext_buf) {
            perror("Failed to allocate memory for ciphertext buffer");
            free(key_buf);
            free(in_buf);
            return EXIT_FAILURE;
        }
        memcpy(ciphertext_buf, in_buf + IV_LEN, ciphertext_len); // Copy ciphertext part
        free(in_buf); // Free the combined IV+ciphertext buffer
        in_buf = NULL; // Avoid dangling pointer

        // Decrypt (in-place in ciphertext_buf)
        AES_CBC_decrypt_buffer(&ctx, ciphertext_buf, ciphertext_len);
        printf("Decryption complete.\n");

        // 6. Unpad Decrypted Data
        size_t unpadded_len;
        if (!pkcs7_unpad(ciphertext_buf, ciphertext_len, &unpadded_len)) {
            fprintf(stderr, "Error: Failed to unpad data. Input may be corrupt or key is wrong.\n");
            free(key_buf);
            free(ciphertext_buf);
            return EXIT_FAILURE;
        }
        printf("Unpadded data to %zu bytes.\n", unpadded_len);


        // 7. Write Plaintext to Output File
        // Note: We write only the unpadded part of ciphertext_buf
        write_file(args.out_fname, ciphertext_buf, unpadded_len);
        printf("Written %zu bytes of plaintext to %s\n", unpadded_len, args.out_fname);

        // Set pointers for cleanup
        out_buf = ciphertext_buf; // Assign for freeing later
        out_len = ciphertext_len; // Store allocated size for freeing

    }

    // --- Cleanup ---
    printf("Cleaning up resources.\n");
    free(key_buf);
    if (in_buf) free(in_buf); // Might be padded_buf
    if (out_buf) free(out_buf); // Might be ciphertext_buf or allocated encrypt buffer

    return EXIT_SUCCESS;
}