#include "common.h"
#include "curve25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <basename>\n", prog);
    fprintf(stderr, "  This will generate <basename>.pub and <basename>.priv key files\n");
    exit(EXIT_FAILURE);
}

// Debug function to print key bytes
static void print_key_bytes(const char* label, const uint8_t* key, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < (len > 8 ? 8 : len); i++) {
        printf("%02x ", key[i]);
    }
    printf("...\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        usage(argv[0]);
    }

    // Create the filenames
    char priv_key_filename[256];
    char pub_key_filename[256];
    snprintf(priv_key_filename, sizeof(priv_key_filename), "%s.priv", argv[1]);
    snprintf(pub_key_filename, sizeof(pub_key_filename), "%s.pub", argv[1]);

    // Generate the keypair
    key_pair_t keypair;
    curve25519_generate_keypair(&keypair);
    /*
    // Debug: Print first few bytes of keys to verify they're not all zeros
    print_key_bytes("Private key", keypair.private_key, FIELD_SIZE);
    print_key_bytes("Public key", keypair.public_key, FIELD_SIZE);
    
    // Check if keys are all zeros
    int all_zeros_private = 1;
    int all_zeros_public = 1;
    
    for (int i = 0; i < FIELD_SIZE; i++) {
        if (keypair.private_key[i] != 0) all_zeros_private = 0;
        if (keypair.public_key[i] != 0) all_zeros_public = 0;
    }
    
    if (all_zeros_private || all_zeros_public) {
        fprintf(stderr, "ERROR: Generated keys contain all zeros!\n");
        return EXIT_FAILURE;
    }
    */
    // Write private key to file
    FILE *f_priv = fopen(priv_key_filename, "wb");
    if (!f_priv) {
        perror("Failed to open private key file");
        return EXIT_FAILURE;
    }
    size_t written = fwrite(keypair.private_key, 1, FIELD_SIZE, f_priv);
    fclose(f_priv);
    
    if (written != FIELD_SIZE) {
        fprintf(stderr, "ERROR: Failed to write complete private key. Wrote %zu of %d bytes\n", 
                written, FIELD_SIZE);
        return EXIT_FAILURE;
    }
    
    // Write public key to file
    FILE *f_pub = fopen(pub_key_filename, "wb");
    if (!f_pub) {
        perror("Failed to open public key file");
        return EXIT_FAILURE;
    }
    written = fwrite(keypair.public_key, 1, FIELD_SIZE, f_pub);
    fclose(f_pub);
    
    if (written != FIELD_SIZE) {
        fprintf(stderr, "ERROR: Failed to write complete public key. Wrote %zu of %d bytes\n", 
                written, FIELD_SIZE);
        return EXIT_FAILURE;
    }

    printf("Private key written to: %s\n", priv_key_filename);
    printf("Public key written to: %s\n", pub_key_filename);

    return 0;
}
