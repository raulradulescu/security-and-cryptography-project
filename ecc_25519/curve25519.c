#include "curve25519.h"
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#endif

typedef int64_t gf[16];

// Constants
static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf _121665 = {0xDB41,1};
static const uint8_t _9[32] = {9};

// Basic operations
static void field_copy(gf r, const gf a) {
    int i;
    for(i = 0; i < 16; i++) r[i] = a[i];
}

static void field_carry(gf o) {
    int i;
    int64_t c;
    for(i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i+1)*(i<15)] += c - 1 + 37*(c-1)*(i==15);
        o[i] -= c << 16;
    }
}

static void conditional_swap(gf p, gf q, int b) {
    int64_t t, i, c = ~(b-1);
    for(i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void field_pack(uint8_t *o, const gf n) {
    int i, j, b;
    gf m, t;
    for(i = 0; i < 16; i++) t[i] = n[i];
    field_carry(t);
    field_carry(t);
    field_carry(t);
    for(j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for(i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        conditional_swap(t, m, 1-b);
    }
    for(i = 0; i < 16; i++) {
        o[2*i] = t[i] & 0xff;
        o[2*i+1] = t[i] >> 8;
    }
}

static void field_unpack(gf o, const uint8_t *n) {
    int i;
    for(i = 0; i < 16; i++) o[i] = n[2*i] + ((int64_t)n[2*i+1] << 8);
    o[15] &= 0x7fff;
}

static void field_add(gf o, const gf a, const gf b) {
    int i;
    for(i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void field_subtract(gf o, const gf a, const gf b) {
    int i;
    for(i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void field_multiply(gf o, const gf a, const gf b) {
    int64_t i, j, t[31];
    for(i = 0; i < 31; i++) t[i] = 0;
    for(i = 0; i < 16; i++) for(j = 0; j < 16; j++) t[i+j] += a[i] * b[j];
    for(i = 0; i < 15; i++) t[i] += 38 * t[i+16];
    for(i = 0; i < 16; i++) o[i] = t[i];
    field_carry(o);
    field_carry(o);
}

static void field_square(gf o, const gf a) {
    field_multiply(o, a, a);
}

static void field_invert(gf o, const gf i) {
    gf c;
    int a;
    for(a = 0; a < 16; a++) c[a] = i[a];
    for(a = 253; a >= 0; a--) {
        field_square(c, c);
        if(a != 2 && a != 4) field_multiply(c, c, i);
    }
    for(a = 0; a < 16; a++) o[a] = c[a];
}

int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    uint8_t z[32];
    int64_t x[80], r, i;
    gf a, b, c, d, e, f;
    
    for(i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    field_unpack(x, p);
    for(i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for(i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        conditional_swap(a, b, r);
        conditional_swap(c, d, r);
        field_add(e, a, c);
        field_subtract(a, a, c);
        field_add(c, b, d);
        field_subtract(b, b, d);
        field_square(d, e);
        field_square(f, a);
        field_multiply(a, c, a);
        field_multiply(c, b, e);
        field_add(e, a, c);
        field_subtract(a, a, c);
        field_square(b, a);
        field_subtract(c, d, f);
        field_multiply(a, c, _121665);
        field_add(a, a, d);
        field_multiply(c, c, a);
        field_multiply(a, d, f);
        field_multiply(d, b, x);
        field_square(b, e);
        conditional_swap(a, b, r);
        conditional_swap(c, d, r);
    }
    for(i = 0; i < 16; i++) {
        x[i+16] = a[i];
        x[i+32] = c[i];
        x[i+48] = b[i];
        x[i+64] = d[i];
    }
    field_invert(x+32, x+32);
    field_multiply(x+16, x+16, x+32);
    field_pack(q, x+16);
    return 0;
}

int crypto_scalarmult_base(uint8_t *q, const uint8_t *n) {
    return crypto_scalarmult(q, n, _9);
}

// Our wrapper functions
void curve25519_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    crypto_scalarmult(q, n, p);
}

void curve25519_compute_public(uint8_t *public_key, const uint8_t *private_key) {
    crypto_scalarmult_base(public_key, private_key);
}

void curve25519_shared_secret(uint8_t *shared, const uint8_t *private_key, const uint8_t *public_key) {
    crypto_scalarmult(shared, private_key, public_key);
}

// Random number generation for key generation
static void get_random_bytes(uint8_t *buffer, size_t size) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)(rand() & 0xFF);
    }
}

void curve25519_generate_keypair(key_pair_t *keypair) {
    get_random_bytes(keypair->private_key, FIELD_SIZE);
    
    // Clamp the private key
    keypair->private_key[0] &= 248;
    keypair->private_key[31] &= 127;
    keypair->private_key[31] |= 64;
    
    curve25519_compute_public(keypair->public_key, keypair->private_key);
}

// Simple XOR-based encryption using a key derived from shared secret
static void stream_xor(uint8_t *c, const uint8_t *m, size_t len, const uint8_t *k) {
    uint8_t keystream[FIELD_SIZE];
    memcpy(keystream, k, FIELD_SIZE);
    
    for (size_t i = 0; i < len; i++) {
        // Rotate key material if needed
        if (i % FIELD_SIZE == 0 && i > 0) {
            uint8_t t = keystream[0];
            for (int j = 0; j < FIELD_SIZE - 1; j++) {
                keystream[j] = keystream[j + 1];
            }
            keystream[FIELD_SIZE - 1] = t;
        }
        c[i] = m[i] ^ keystream[i % FIELD_SIZE];
    }
}

int ecc_encrypt(const uint8_t *public_key, const uint8_t *plaintext, 
                size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len) {
    
    // Generate ephemeral key pair
    key_pair_t ephemeral;
    curve25519_generate_keypair(&ephemeral);
    
    // Compute shared secret
    uint8_t shared_secret[FIELD_SIZE];
    curve25519_shared_secret(shared_secret, ephemeral.private_key, public_key);
    
    // Allocate ciphertext: ephemeral public key + encrypted data
    *ciphertext_len = FIELD_SIZE + plaintext_len;
    *ciphertext = malloc(*ciphertext_len);
    if (*ciphertext == NULL) {
        return 0; // Return 0 for failure
    }
    
    // Store ephemeral public key at the beginning
    memcpy(*ciphertext, ephemeral.public_key, FIELD_SIZE);
    
    // Encrypt the plaintext using XOR with shared secret
    stream_xor(*ciphertext + FIELD_SIZE, plaintext, plaintext_len, shared_secret);
    
    return 1; // Return 1 for success
}

int ecc_decrypt(const uint8_t *private_key, const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len) {
    
    if (ciphertext_len < FIELD_SIZE) {
        return 0; // Return 0 for failure
    }
    
    // Extract ephemeral public key
    const uint8_t *ephemeral_public_key = ciphertext;
    
    // Compute shared secret
    uint8_t shared_secret[FIELD_SIZE];
    curve25519_shared_secret(shared_secret, private_key, ephemeral_public_key);
    
    // Allocate plaintext
    *plaintext_len = ciphertext_len - FIELD_SIZE;
    *plaintext = malloc(*plaintext_len);
    if (*plaintext == NULL) {
        return 0; // Return 0 for failure
    }
    
    // Decrypt the ciphertext using XOR with shared secret
    stream_xor(*plaintext, ciphertext + FIELD_SIZE, *plaintext_len, shared_secret);
    
    return 1; // Return 1 for success
}

// Key file handling functions
int read_key(const char *filename, uint8_t *key, crypto_mode_t mode) {
    (void)mode; // Suppress unused parameter warning
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Error: Could not open key file %s\n", filename);
        return 0; // Return 0 for failure to match expected usage
    }
    
    // Always read FIELD_SIZE bytes for both public and private keys
    if (fread(key, 1, FIELD_SIZE, file) != FIELD_SIZE) {
        printf("Error: Could not read key\n");
        fclose(file);
        return 0; // Return 0 for failure
    }
    
    fclose(file);
    return 1; // Return 1 for success
}

void generate_and_save_keypair(const char *filename) {
    key_pair_t keypair;
    curve25519_generate_keypair(&keypair);
    
    char private_filename[256];
    char public_filename[256];
    
    snprintf(private_filename, sizeof(private_filename), "%s.priv", filename);
    snprintf(public_filename, sizeof(public_filename), "%s.pub", filename);
    
    FILE *priv_file = fopen(private_filename, "wb");
    if (priv_file) {
        fwrite(keypair.private_key, 1, FIELD_SIZE, priv_file);
        fclose(priv_file);
        printf("Private key saved to %s\n", private_filename);
    } else {
        printf("Error: Could not save private key\n");
    }
    
    FILE *pub_file = fopen(public_filename, "wb");
    if (pub_file) {
        fwrite(keypair.public_key, 1, FIELD_SIZE, pub_file);
        fclose(pub_file);
        printf("Public key saved to %s\n", public_filename);
    } else {
        printf("Error: Could not save public key\n");
    }
}
