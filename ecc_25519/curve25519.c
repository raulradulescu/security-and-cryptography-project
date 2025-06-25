#include "curve25519.h"
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

// Curve25519 parameters
// The prime field: 2^255 - 19
static const uint8_t CURVE25519_PRIME[32] = {
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
};

// Constant value A for Montgomery curve (486662)
const uint8_t CURVE25519_A[FIELD_SIZE] = {
    0x06, 0x6D, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Base point (9)
static const uint8_t CURVE25519_BASE[32] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Typedef for 64-bit intermediate calculations
typedef int64_t fe[16];  // Use radix 2^16 representation internally

// Convert from bytes to field element
static void fe_frombytes(fe h, const uint8_t *s) {
    int64_t h0 = s[0] | (s[1] << 8);
    int64_t h1 = s[2] | (s[3] << 8);
    int64_t h2 = s[4] | (s[5] << 8);
    int64_t h3 = s[6] | (s[7] << 8);
    int64_t h4 = s[8] | (s[9] << 8);
    int64_t h5 = s[10] | (s[11] << 8);
    int64_t h6 = s[12] | (s[13] << 8);
    int64_t h7 = s[14] | (s[15] << 8);
    int64_t h8 = s[16] | (s[17] << 8);
    int64_t h9 = s[18] | (s[19] << 8);
    int64_t h10 = s[20] | (s[21] << 8);
    int64_t h11 = s[22] | (s[23] << 8);
    int64_t h12 = s[24] | (s[25] << 8);
    int64_t h13 = s[26] | (s[27] << 8);
    int64_t h14 = s[28] | (s[29] << 8);
    int64_t h15 = s[30] | (s[31] << 8);

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3;
    h[4] = h4; h[5] = h5; h[6] = h6; h[7] = h7;
    h[8] = h8; h[9] = h9; h[10] = h10; h[11] = h11;
    h[12] = h12; h[13] = h13; h[14] = h14; h[15] = h15;
}

// Convert from field element to bytes
static void fe_tobytes(uint8_t *s, const fe h) {
    fe carry;
    memcpy(carry, h, sizeof(fe));
    
    // Reduce modulo 2^255 - 19
    int64_t q = (19 * carry[15] + (1 << 24)) >> 25;
    q = (carry[0] + q) >> 26;
    q = (carry[1] + q) >> 25;
    q = (carry[2] + q) >> 26;
    q = (carry[3] + q) >> 25;
    q = (carry[4] + q) >> 26;
    q = (carry[5] + q) >> 25;
    q = (carry[6] + q) >> 26;
    q = (carry[7] + q) >> 25;
    q = (carry[8] + q) >> 26;
    q = (carry[9] + q) >> 25;
    q = (carry[10] + q) >> 26;
    q = (carry[11] + q) >> 25;
    q = (carry[12] + q) >> 26;
    q = (carry[13] + q) >> 25;
    q = (carry[14] + q) >> 26;
    q = (carry[15] + q) >> 25;

    carry[0] += 19 * q;

    // Propagate carries
    carry[1] += carry[0] >> 26; carry[0] &= 0x3ffffff;
    carry[2] += carry[1] >> 25; carry[1] &= 0x1ffffff;
    carry[3] += carry[2] >> 26; carry[2] &= 0x3ffffff;
    carry[4] += carry[3] >> 25; carry[3] &= 0x1ffffff;
    carry[5] += carry[4] >> 26; carry[4] &= 0x3ffffff;
    carry[6] += carry[5] >> 25; carry[5] &= 0x1ffffff;
    carry[7] += carry[6] >> 26; carry[6] &= 0x3ffffff;
    carry[8] += carry[7] >> 25; carry[7] &= 0x1ffffff;
    carry[9] += carry[8] >> 26; carry[8] &= 0x3ffffff;
    carry[10] += carry[9] >> 25; carry[9] &= 0x1ffffff;
    carry[11] += carry[10] >> 26; carry[10] &= 0x3ffffff;
    carry[12] += carry[11] >> 25; carry[11] &= 0x1ffffff;
    carry[13] += carry[12] >> 26; carry[12] &= 0x3ffffff;
    carry[14] += carry[13] >> 25; carry[13] &= 0x1ffffff;
    carry[15] += carry[14] >> 26; carry[14] &= 0x3ffffff;
    carry[15] &= 0x1ffffff;

    s[0] = carry[0] & 0xff; s[1] = carry[0] >> 8;
    s[2] = carry[1] & 0xff; s[3] = carry[1] >> 8;
    s[4] = carry[2] & 0xff; s[5] = carry[2] >> 8;
    s[6] = carry[3] & 0xff; s[7] = carry[3] >> 8;
    s[8] = carry[4] & 0xff; s[9] = carry[4] >> 8;
    s[10] = carry[5] & 0xff; s[11] = carry[5] >> 8;
    s[12] = carry[6] & 0xff; s[13] = carry[6] >> 8;
    s[14] = carry[7] & 0xff; s[15] = carry[7] >> 8;
    s[16] = carry[8] & 0xff; s[17] = carry[8] >> 8;
    s[18] = carry[9] & 0xff; s[19] = carry[9] >> 8;
    s[20] = carry[10] & 0xff; s[21] = carry[10] >> 8;
    s[22] = carry[11] & 0xff; s[23] = carry[11] >> 8;
    s[24] = carry[12] & 0xff; s[25] = carry[12] >> 8;
    s[26] = carry[13] & 0xff; s[27] = carry[13] >> 8;
    s[28] = carry[14] & 0xff; s[29] = carry[14] >> 8;
    s[30] = carry[15] & 0xff; s[31] = carry[15] >> 8;
}

// Field operations
static void fe_copy(fe h, const fe f) {
    memcpy(h, f, sizeof(fe));
}

static void fe_0(fe h) {
    memset(h, 0, sizeof(fe));
}

static void fe_1(fe h) {
    memset(h, 0, sizeof(fe));
    h[0] = 1;
}


// Modular addition in F_p where p = 2^255 - 19
static void fe_add(fe h, const fe f, const fe g) {
    for(int i = 0; i < 16; i++) {
        h[i] = f[i] + g[i];
    }
}

// Modular subtraction in F_p
static void fe_sub(fe h, const fe f, const fe g) {
    for(int i = 0; i < 16; i++) {
        h[i] = f[i] - g[i];
    }
}


// Modular multiplication in F_p
static void fe_mul(fe h, const fe f, const fe g) {
    int64_t f0 = f[0]; int64_t f1 = f[1]; int64_t f2 = f[2]; int64_t f3 = f[3];
    int64_t f4 = f[4]; int64_t f5 = f[5]; int64_t f6 = f[6]; int64_t f7 = f[7];
    int64_t f8 = f[8]; int64_t f9 = f[9]; int64_t f10 = f[10]; int64_t f11 = f[11];
    int64_t f12 = f[12]; int64_t f13 = f[13]; int64_t f14 = f[14]; int64_t f15 = f[15];

    int64_t g0 = g[0]; int64_t g1 = g[1]; int64_t g2 = g[2]; int64_t g3 = g[3];
    int64_t g4 = g[4]; int64_t g5 = g[5]; int64_t g6 = g[6]; int64_t g7 = g[7];
    int64_t g8 = g[8]; int64_t g9 = g[9]; int64_t g10 = g[10]; int64_t g11 = g[11];
    int64_t g12 = g[12]; int64_t g13 = g[13]; int64_t g14 = g[14]; int64_t g15 = g[15];

    // Precompute g_i * 19 for reduction modulo 2^255 - 19
    int64_t g1_19 = 19 * g1; int64_t g2_19 = 19 * g2; int64_t g3_19 = 19 * g3;
    int64_t g4_19 = 19 * g4; int64_t g5_19 = 19 * g5; int64_t g6_19 = 19 * g6;
    int64_t g7_19 = 19 * g7; int64_t g8_19 = 19 * g8; int64_t g9_19 = 19 * g9;
    int64_t g10_19 = 19 * g10; int64_t g11_19 = 19 * g11; int64_t g12_19 = 19 * g12;
    int64_t g13_19 = 19 * g13; int64_t g14_19 = 19 * g14; int64_t g15_19 = 19 * g15;

    // Precompute 2 * f_i for odd indices (doubling optimization)
    int64_t f1_2 = 2 * f1; int64_t f3_2 = 2 * f3; int64_t f5_2 = 2 * f5;
    int64_t f7_2 = 2 * f7; int64_t f9_2 = 2 * f9; int64_t f11_2 = 2 * f11;
    int64_t f13_2 = 2 * f13; int64_t f15_2 = 2 * f15;

    // Compute all cross products
    int64_t f0g0 = f0 * g0; int64_t f0g1 = f0 * g1; int64_t f0g2 = f0 * g2;
    int64_t f0g3 = f0 * g3; int64_t f0g4 = f0 * g4; int64_t f0g5 = f0 * g5;
    int64_t f0g6 = f0 * g6; int64_t f0g7 = f0 * g7; int64_t f0g8 = f0 * g8;
    int64_t f0g9 = f0 * g9; int64_t f0g10 = f0 * g10; int64_t f0g11 = f0 * g11;
    int64_t f0g12 = f0 * g12; int64_t f0g13 = f0 * g13; int64_t f0g14 = f0 * g14;
    int64_t f0g15 = f0 * g15;

    int64_t f1g0 = f1 * g0; int64_t f1g1_2 = f1_2 * g1; int64_t f1g2 = f1 * g2;
    int64_t f1g3_2 = f1_2 * g3; int64_t f1g4 = f1 * g4; int64_t f1g5_2 = f1_2 * g5;
    int64_t f1g6 = f1 * g6; int64_t f1g7_2 = f1_2 * g7; int64_t f1g8 = f1 * g8;
    int64_t f1g9_2 = f1_2 * g9; int64_t f1g10 = f1 * g10; int64_t f1g11_2 = f1_2 * g11;
    int64_t f1g12 = f1 * g12; int64_t f1g13_2 = f1_2 * g13; int64_t f1g14 = f1 * g14;
    int64_t f1g15_2 = f1_2 * g15;

    int64_t f2g0 = f2 * g0; int64_t f2g1 = f2 * g1; int64_t f2g2 = f2 * g2;
    int64_t f2g3 = f2 * g3; int64_t f2g4 = f2 * g4; int64_t f2g5 = f2 * g5;
    int64_t f2g6 = f2 * g6; int64_t f2g7 = f2 * g7; int64_t f2g8 = f2 * g8;
    int64_t f2g9 = f2 * g9; int64_t f2g10 = f2 * g10; int64_t f2g11 = f2 * g11;
    int64_t f2g12 = f2 * g12; int64_t f2g13 = f2 * g13; int64_t f2g14 = f2 * g14;
    int64_t f2g15 = f2 * g15;

    int64_t f3g0 = f3 * g0; int64_t f3g1_2 = f3_2 * g1; int64_t f3g2 = f3 * g2;
    int64_t f3g3_2 = f3_2 * g3; int64_t f3g4 = f3 * g4; int64_t f3g5_2 = f3_2 * g5;
    int64_t f3g6 = f3 * g6; int64_t f3g7_2 = f3_2 * g7; int64_t f3g8 = f3 * g8;
    int64_t f3g9_2 = f3_2 * g9; int64_t f3g10 = f3 * g10; int64_t f3g11_2 = f3_2 * g11;
    int64_t f3g12 = f3 * g12; int64_t f3g13_2 = f3_2 * g13; int64_t f3g14 = f3 * g14;
    int64_t f3g15_2 = f3_2 * g15;

    int64_t f4g0 = f4 * g0; int64_t f4g1 = f4 * g1; int64_t f4g2 = f4 * g2;
    int64_t f4g3 = f4 * g3; int64_t f4g4 = f4 * g4; int64_t f4g5 = f4 * g5;
    int64_t f4g6 = f4 * g6; int64_t f4g7 = f4 * g7; int64_t f4g8 = f4 * g8;
    int64_t f4g9 = f4 * g9; int64_t f4g10 = f4 * g10; int64_t f4g11 = f4 * g11;
    int64_t f4g12 = f4 * g12; int64_t f4g13 = f4 * g13; int64_t f4g14 = f4 * g14;
    int64_t f4g15 = f4 * g15;

    int64_t f5g0 = f5 * g0; int64_t f5g1_2 = f5_2 * g1; int64_t f5g2 = f5 * g2;
    int64_t f5g3_2 = f5_2 * g3; int64_t f5g4 = f5 * g4; int64_t f5g5_2 = f5_2 * g5;
    int64_t f5g6 = f5 * g6; int64_t f5g7_2 = f5_2 * g7; int64_t f5g8 = f5 * g8;
    int64_t f5g9_2 = f5_2 * g9; int64_t f5g10 = f5 * g10; int64_t f5g11_2 = f5_2 * g11;
    int64_t f5g12 = f5 * g12; int64_t f5g13_2 = f5_2 * g13; int64_t f5g14 = f5 * g14;
    int64_t f5g15_2 = f5_2 * g15;

    int64_t f6g0 = f6 * g0; int64_t f6g1 = f6 * g1; int64_t f6g2 = f6 * g2;
    int64_t f6g3 = f6 * g3; int64_t f6g4 = f6 * g4; int64_t f6g5 = f6 * g5;
    int64_t f6g6 = f6 * g6; int64_t f6g7 = f6 * g7; int64_t f6g8 = f6 * g8;
    int64_t f6g9 = f6 * g9; int64_t f6g10 = f6 * g10; int64_t f6g11 = f6 * g11;
    int64_t f6g12 = f6 * g12; int64_t f6g13 = f6 * g13; int64_t f6g14 = f6 * g14;
    int64_t f6g15 = f6 * g15;

    int64_t f7g0 = f7 * g0; int64_t f7g1_2 = f7_2 * g1; int64_t f7g2 = f7 * g2;
    int64_t f7g3_2 = f7_2 * g3; int64_t f7g4 = f7 * g4; int64_t f7g5_2 = f7_2 * g5;
    int64_t f7g6 = f7 * g6; int64_t f7g7_2 = f7_2 * g7; int64_t f7g8 = f7 * g8;
    int64_t f7g9_2 = f7_2 * g9; int64_t f7g10 = f7 * g10; int64_t f7g11_2 = f7_2 * g11;
    int64_t f7g12 = f7 * g12; int64_t f7g13_2 = f7_2 * g13; int64_t f7g14 = f7 * g14;
    int64_t f7g15_2 = f7_2 * g15;

    int64_t f8g0 = f8 * g0; int64_t f8g1 = f8 * g1; int64_t f8g2 = f8 * g2;
    int64_t f8g3 = f8 * g3; int64_t f8g4 = f8 * g4; int64_t f8g5 = f8 * g5;
    int64_t f8g6 = f8 * g6; int64_t f8g7 = f8 * g7; int64_t f8g8 = f8 * g8;
    int64_t f8g9 = f8 * g9; int64_t f8g10 = f8 * g10; int64_t f8g11 = f8 * g11;
    int64_t f8g12 = f8 * g12; int64_t f8g13 = f8 * g13; int64_t f8g14 = f8 * g14;
    int64_t f8g15 = f8 * g15;

    int64_t f9g0 = f9 * g0; int64_t f9g1_2 = f9_2 * g1; int64_t f9g2 = f9 * g2;
    int64_t f9g3_2 = f9_2 * g3; int64_t f9g4 = f9 * g4; int64_t f9g5_2 = f9_2 * g5;
    int64_t f9g6 = f9 * g6; int64_t f9g7_2 = f9_2 * g7; int64_t f9g8 = f9 * g8;
    int64_t f9g9_2 = f9_2 * g9; int64_t f9g10 = f9 * g10; int64_t f9g11_2 = f9_2 * g11;
    int64_t f9g12 = f9 * g12; int64_t f9g13_2 = f9_2 * g13; int64_t f9g14 = f9 * g14;
    int64_t f9g15_2 = f9_2 * g15;

    int64_t f10g0 = f10 * g0; int64_t f10g1 = f10 * g1; int64_t f10g2 = f10 * g2;
    int64_t f10g3 = f10 * g3; int64_t f10g4 = f10 * g4; int64_t f10g5 = f10 * g5;
    int64_t f10g6 = f10 * g6; int64_t f10g7 = f10 * g7; int64_t f10g8 = f10 * g8;
    int64_t f10g9 = f10 * g9; int64_t f10g10 = f10 * g10; int64_t f10g11 = f10 * g11;
    int64_t f10g12 = f10 * g12; int64_t f10g13 = f10 * g13; int64_t f10g14 = f10 * g14;
    int64_t f10g15 = f10 * g15;

    int64_t f11g0 = f11 * g0; int64_t f11g1_2 = f11_2 * g1; int64_t f11g2 = f11 * g2;
    int64_t f11g3_2 = f11_2 * g3; int64_t f11g4 = f11 * g4; int64_t f11g5_2 = f11_2 * g5;
    int64_t f11g6 = f11 * g6; int64_t f11g7_2 = f11_2 * g7; int64_t f11g8 = f11 * g8;
    int64_t f11g9_2 = f11_2 * g9; int64_t f11g10 = f11 * g10; int64_t f11g11_2 = f11_2 * g11;
    int64_t f11g12 = f11 * g12; int64_t f11g13_2 = f11_2 * g13; int64_t f11g14 = f11 * g14;
    int64_t f11g15_2 = f11_2 * g15;

    int64_t f12g0 = f12 * g0; int64_t f12g1 = f12 * g1; int64_t f12g2 = f12 * g2;
    int64_t f12g3 = f12 * g3; int64_t f12g4 = f12 * g4; int64_t f12g5 = f12 * g5;
    int64_t f12g6 = f12 * g6; int64_t f12g7 = f12 * g7; int64_t f12g8 = f12 * g8;
    int64_t f12g9 = f12 * g9; int64_t f12g10 = f12 * g10; int64_t f12g11 = f12 * g11;
    int64_t f12g12 = f12 * g12; int64_t f12g13 = f12 * g13; int64_t f12g14 = f12 * g14;
    int64_t f12g15 = f12 * g15;

    int64_t f13g0 = f13 * g0; int64_t f13g1_2 = f13_2 * g1; int64_t f13g2 = f13 * g2;
    int64_t f13g3_2 = f13_2 * g3; int64_t f13g4 = f13 * g4; int64_t f13g5_2 = f13_2 * g5;
    int64_t f13g6 = f13 * g6; int64_t f13g7_2 = f13_2 * g7; int64_t f13g8 = f13 * g8;
    int64_t f13g9_2 = f13_2 * g9; int64_t f13g10 = f13 * g10; int64_t f13g11_2 = f13_2 * g11;
    int64_t f13g12 = f13 * g12; int64_t f13g13_2 = f13_2 * g13; int64_t f13g14 = f13 * g14;
    int64_t f13g15_2 = f13_2 * g15;

    int64_t f14g0 = f14 * g0; int64_t f14g1 = f14 * g1; int64_t f14g2 = f14 * g2;
    int64_t f14g3 = f14 * g3; int64_t f14g4 = f14 * g4; int64_t f14g5 = f14 * g5;
    int64_t f14g6 = f14 * g6; int64_t f14g7 = f14 * g7; int64_t f14g8 = f14 * g8;
    int64_t f14g9 = f14 * g9; int64_t f14g10 = f14 * g10; int64_t f14g11 = f14 * g11;
    int64_t f14g12 = f14 * g12; int64_t f14g13 = f14 * g13; int64_t f14g14 = f14 * g14;
    int64_t f14g15 = f14 * g15;

    int64_t f15g0 = f15 * g0; int64_t f15g1_2 = f15_2 * g1; int64_t f15g2 = f15 * g2;
    int64_t f15g3_2 = f15_2 * g3; int64_t f15g4 = f15 * g4; int64_t f15g5_2 = f15_2 * g5;
    int64_t f15g6 = f15 * g6; int64_t f15g7_2 = f15_2 * g7; int64_t f15g8 = f15 * g8;
    int64_t f15g9_2 = f15_2 * g9; int64_t f15g10 = f15 * g10; int64_t f15g11_2 = f15_2 * g11;
    int64_t f15g12 = f15 * g12; int64_t f15g13_2 = f15_2 * g13; int64_t f15g14 = f15 * g14;
    int64_t f15g15_2 = f15_2 * g15;

    // Add missing variable declarations for multiplication by g15
    int64_t f1g15 = f1 * g15; 
    int64_t f3g15 = f3 * g15; 
    int64_t f5g15 = f5 * g15;
    int64_t f7g15 = f7 * g15; 
    int64_t f9g15 = f9 * g15; 
    int64_t f11g15 = f11 * g15; 
    int64_t f13g15 = f13 * g15;
    int64_t f15g15 = f15 * g15;

    // Combine cross products to form the result coefficients
    // When multiplying, terms like f_i * g_j contribute to coefficient (i+j)
    // But since we're working modulo 2^255 - 19, terms with i+j >= 16 get multiplied by 19
    
    int64_t h0 = f0g0  + f1g15_2 + f2g14  + f3g13_2 + f4g12  + f5g11_2 + f6g10  + f7g9_2  + f8g8   + f9g7_2  + f10g6  + f11g5_2 + f12g4  + f13g3_2 + f14g2  + f15g1_2;
    int64_t h1 = f0g1  + f1g0    + f2g15  + f3g14   + f4g13  + f5g12   + f6g11  + f7g10   + f8g9   + f9g8    + f10g7  + f11g6   + f12g5  + f13g4   + f14g3  + f15g2;
    int64_t h2 = f0g2  + f1g1_2  + f2g0   + f3g15_2 + f4g14  + f5g13_2 + f6g12  + f7g11_2 + f8g10  + f9g9_2  + f10g8  + f11g7_2 + f12g6  + f13g5_2 + f14g4  + f15g3_2;
    int64_t h3 = f0g3  + f1g2    + f2g1   + f3g0    + f4g15  + f5g14   + f6g13  + f7g12   + f8g11  + f9g10   + f10g9  + f11g8   + f12g7  + f13g6   + f14g5  + f15g4;
    int64_t h4 = f0g4  + f1g3_2  + f2g2   + f3g1_2  + f4g0   + f5g15_2 + f6g14  + f7g13_2 + f8g12  + f9g11_2 + f10g10 + f11g9_2 + f12g8  + f13g7_2 + f14g6  + f15g5_2;
    int64_t h5 = f0g5  + f1g4    + f2g3   + f3g2    + f4g1   + f5g0    + f6g15  + f7g14   + f8g13  + f9g12   + f10g11 + f11g10  + f12g9  + f13g8   + f14g7  + f15g6;
    int64_t h6 = f0g6  + f1g5_2  + f2g4   + f3g3_2  + f4g2   + f5g1_2  + f6g0   + f7g15_2 + f8g14  + f9g13_2 + f10g12 + f11g11_2+ f12g10 + f13g9_2 + f14g8  + f15g7_2;
    int64_t h7 = f0g7  + f1g6    + f2g5   + f3g4    + f4g3   + f5g2    + f6g1   + f7g0    + f8g15  + f9g14   + f10g13 + f11g12  + f12g11 + f13g10  + f14g9  + f15g8;
    int64_t h8 = f0g8  + f1g7_2  + f2g6   + f3g5_2  + f4g4   + f5g3_2  + f6g2   + f7g1_2  + f8g0   + f9g15_2 + f10g14 + f11g13_2+ f12g12 + f13g11_2+ f14g10 + f15g9_2;
    int64_t h9 = f0g9  + f1g8    + f2g7   + f3g6    + f4g5   + f5g4    + f6g3   + f7g2    + f8g1   + f9g0    + f10g15 + f11g14  + f12g13 + f13g12  + f14g11 + f15g10;
    int64_t h10= f0g10 + f1g9_2  + f2g8   + f3g7_2  + f4g6   + f5g5_2  + f6g4   + f7g3_2  + f8g2   + f9g1_2  + f10g0  + f11g15_2+ f12g14 + f13g13_2+ f14g12 + f15g11_2;
    int64_t h11= f0g11 + f1g10   + f2g9   + f3g8    + f4g7   + f5g6    + f6g5   + f7g4    + f8g3   + f9g2    + f10g1  + f11g0   + f12g15 + f13g14  + f14g13 + f15g12;
    int64_t h12= f0g12 + f1g11_2 + f2g10  + f3g9_2  + f4g8   + f5g7_2  + f6g6   + f7g5_2  + f8g4   + f9g3_2  + f10g2  + f11g1_2 + f12g0  + f13g15_2+ f14g14 + f15g13_2;
    int64_t h13= f0g13 + f1g12   + f2g11  + f3g10   + f4g9   + f5g8    + f6g7   + f7g6    + f8g5   + f9g4    + f10g3  + f11g2   + f12g1  + f13g0   + f14g15 + f15g14;
    int64_t h14= f0g14 + f1g13_2 + f2g12  + f3g11_2 + f4g10  + f5g9_2  + f6g8   + f7g7_2  + f8g6   + f9g5_2  + f10g4  + f11g3_2 + f12g2  + f13g1_2 + f14g0  + f15g15_2;
    int64_t h15= f0g15 + f1g14   + f2g13  + f3g12   + f4g11  + f5g10   + f6g9   + f7g8    + f8g7   + f9g6    + f10g5  + f11g4   + f12g3  + f13g2   + f14g1  + f15g0;

    // Multiply high terms by 19 for modular reduction
    h0 += 19 * (f1g15 + f2g15 + f3g15 + f4g15 + f5g15 + f6g15 + f7g15 + f8g15 + 
                f9g15 + f10g15 + f11g15 + f12g15 + f13g15 + f14g15 + f15g15);

    // Store result
    h[0] = h0;   h[1] = h1;   h[2] = h2;   h[3] = h3;
    h[4] = h4;   h[5] = h5;   h[6] = h6;   h[7] = h7;
    h[8] = h8;   h[9] = h9;   h[10] = h10; h[11] = h11;
    h[12] = h12; h[13] = h13; h[14] = h14; h[15] = h15;
}

// Modular squaring: h = f^2
// Optimized squaring function (more efficient than general multiplication)
static void fe_sq(fe h, const fe f) {
    int64_t f0 = f[0]; int64_t f1 = f[1]; int64_t f2 = f[2]; int64_t f3 = f[3];
    int64_t f4 = f[4]; int64_t f5 = f[5]; int64_t f6 = f[6]; int64_t f7 = f[7];
    int64_t f8 = f[8]; int64_t f9 = f[9]; int64_t f10 = f[10]; int64_t f11 = f[11];
    int64_t f12 = f[12]; int64_t f13 = f[13]; int64_t f14 = f[14]; int64_t f15 = f[15];

    // Precompute doubled values for cross terms
    int64_t f0_2 = 2 * f0; int64_t f1_2 = 2 * f1; int64_t f2_2 = 2 * f2; int64_t f3_2 = 2 * f3;
    int64_t f4_2 = 2 * f4; int64_t f5_2 = 2 * f5; int64_t f6_2 = 2 * f6; int64_t f7_2 = 2 * f7;
    int64_t f8_2 = 2 * f8; int64_t f9_2 = 2 * f9; int64_t f10_2 = 2 * f10; int64_t f11_2 = 2 * f11;
    int64_t f12_2 = 2 * f12; int64_t f13_2 = 2 * f13; int64_t f14_2 = 2 * f14; int64_t f15_2 = 2 * f15;

    // Precompute 19 * f_i for high-degree terms that need reduction
    int64_t f1_19 = 19 * f1; int64_t f2_19 = 19 * f2; int64_t f3_19 = 19 * f3;
    int64_t f4_19 = 19 * f4; int64_t f5_19 = 19 * f5; int64_t f6_19 = 19 * f6;
    int64_t f7_19 = 19 * f7; int64_t f8_19 = 19 * f8; int64_t f9_19 = 19 * f9;
    int64_t f10_19 = 19 * f10; int64_t f11_19 = 19 * f11; int64_t f12_19 = 19 * f12;
    int64_t f13_19 = 19 * f13; int64_t f14_19 = 19 * f14; int64_t f15_19 = 19 * f15;

    // Precompute 2 * 19 * f_i for cross terms with high degree
    int64_t f1_38 = 38 * f1; int64_t f2_38 = 38 * f2; int64_t f3_38 = 38 * f3;
    int64_t f4_38 = 38 * f4; int64_t f5_38 = 38 * f5; int64_t f6_38 = 38 * f6;
    int64_t f7_38 = 38 * f7; int64_t f8_38 = 38 * f8; int64_t f9_38 = 38 * f9;
    int64_t f10_38 = 38 * f10; int64_t f11_38 = 38 * f11; int64_t f12_38 = 38 * f12;
    int64_t f13_38 = 38 * f13; int64_t f14_38 = 38 * f14; int64_t f15_38 = 38 * f15;

    // Compute coefficients of the squared polynomial
    // Each coefficient h_i is the sum of f_j * f_k where j + k = i (mod 16)
    // For squaring, we can optimize by computing each cross product only once
    
    int64_t h0 = f0 * f0 + f1_38 * f15 + f2_38 * f14 + f3_38 * f13 + f4_38 * f12 + 
                 f5_38 * f11 + f6_38 * f10 + f7_38 * f9 + f8_19 * f8;
    
    int64_t h1 = f0_2 * f1 + f2_38 * f15 + f3_38 * f14 + f4_38 * f13 + f5_38 * f12 + 
                 f6_38 * f11 + f7_38 * f10 + f8_38 * f9;
    
    int64_t h2 = f0_2 * f2 + f1 * f1 + f3_38 * f15 + f4_38 * f14 + f5_38 * f13 + 
                 f6_38 * f12 + f7_38 * f11 + f8_38 * f10 + f9_19 * f9;
    
    int64_t h3 = f0_2 * f3 + f1_2 * f2 + f4_38 * f15 + f5_38 * f14 + f6_38 * f13 + 
                 f7_38 * f12 + f8_38 * f11 + f9_38 * f10;
    
    int64_t h4 = f0_2 * f4 + f1_2 * f3 + f2 * f2 + f5_38 * f15 + f6_38 * f14 + 
                 f7_38 * f13 + f8_38 * f12 + f9_38 * f11 + f10_19 * f10;
    
    int64_t h5 = f0_2 * f5 + f1_2 * f4 + f2_2 * f3 + f6_38 * f15 + f7_38 * f14 + 
                 f8_38 * f13 + f9_38 * f12 + f10_38 * f11;
    
    int64_t h6 = f0_2 * f6 + f1_2 * f5 + f2_2 * f4 + f3 * f3 + f7_38 * f15 + 
                 f8_38 * f14 + f9_38 * f13 + f10_38 * f12 + f11_19 * f11;
    
    int64_t h7 = f0_2 * f7 + f1_2 * f6 + f2_2 * f5 + f3_2 * f4 + f8_38 * f15 + 
                 f9_38 * f14 + f10_38 * f13 + f11_38 * f12;
    
    int64_t h8 = f0_2 * f8 + f1_2 * f7 + f2_2 * f6 + f3_2 * f5 + f4 * f4 + 
                 f9_38 * f15 + f10_38 * f14 + f11_38 * f13 + f12_19 * f12;
    
    int64_t h9 = f0_2 * f9 + f1_2 * f8 + f2_2 * f7 + f3_2 * f6 + f4_2 * f5 + 
                 f10_38 * f15 + f11_38 * f14 + f12_38 * f13;
    
    int64_t h10 = f0_2 * f10 + f1_2 * f9 + f2_2 * f8 + f3_2 * f7 + f4_2 * f6 + 
                  f5 * f5 + f11_38 * f15 + f12_38 * f14 + f13_19 * f13;
    
    int64_t h11 = f0_2 * f11 + f1_2 * f10 + f2_2 * f9 + f3_2 * f8 + f4_2 * f7 + 
                  f5_2 * f6 + f12_38 * f15 + f13_38 * f14;
    
    int64_t h12 = f0_2 * f12 + f1_2 * f11 + f2_2 * f10 + f3_2 * f9 + f4_2 * f8 + 
                  f5_2 * f7 + f6 * f6 + f13_38 * f15 + f14_19 * f14;
    
    int64_t h13 = f0_2 * f13 + f1_2 * f12 + f2_2 * f11 + f3_2 * f10 + f4_2 * f9 + 
                  f5_2 * f8 + f6_2 * f7 + f14_38 * f15;
    
    int64_t h14 = f0_2 * f14 + f1_2 * f13 + f2_2 * f12 + f3_2 * f11 + f4_2 * f10 + 
                  f5_2 * f9 + f6_2 * f8 + f7 * f7 + f15_19 * f15;
    
    int64_t h15 = f0_2 * f15 + f1_2 * f14 + f2_2 * f13 + f3_2 * f12 + f4_2 * f11 + 
                  f5_2 * f10 + f6_2 * f9 + f7_2 * f8;

    // Store the result
    h[0] = h0;   h[1] = h1;   h[2] = h2;   h[3] = h3;
    h[4] = h4;   h[5] = h5;   h[6] = h6;   h[7] = h7;
    h[8] = h8;   h[9] = h9;   h[10] = h10; h[11] = h11;
    h[12] = h12; h[13] = h13; h[14] = h14; h[15] = h15;
}

// Inversion: h = 1/f
// Uses Fermat's Little Theorem: f^(p-2) ≡ 1/f (mod p)
static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;

    // z^2
    fe_sq(t0, z);
    
    // z^3
    fe_mul(t1, t0, z);
    
    // z^6
    fe_sq(t0, t1);
    for (i = 1; i < 3; ++i) {
        fe_sq(t0, t0);
    }
    
    // z^9
    fe_mul(t0, t0, t1);
    
    // z^11
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    
    // z^20
    fe_mul(t0, t1, t0);
    
    // z^40
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe_sq(t1, t1);
    }
    
    // z^50
    fe_mul(t0, t1, t0);
    
    // z^100
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    
    // z^150
    fe_mul(t1, t1, t0);
    
    // z^200
    fe_sq(t2, t1);
    for (i = 1; i < 25; ++i) {
        fe_sq(t2, t2);
    }
    
    // z^250
    fe_mul(t1, t2, t1);
    
    // z^252
    fe_sq(t1, t1);
    fe_sq(t1, t1);
    
    // z^253
    fe_mul(out, t1, z);
}

// Forward declaration to fix the ordering issue
static void fe_cswap(fe f, fe g, unsigned int b);

// Corrected Montgomery ladder for Curve25519
static void curve25519_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    // Create working buffers
    unsigned char scalar[32];
    unsigned char x1[32], x2[32], z2[32], x3[32], z3[32];
    unsigned char a[32], b[32], c[32], d[32], e[32], f[32];
    unsigned char swap = 0;
    int pos;
    fe t1, t2, zinv; // Add declaration for t1, t2, and zinv here
    
    // Copy and clamp the scalar
    memcpy(scalar, n, 32);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    // Initialize points
    memcpy(x1, p, 32);
    memset(x2, 0, 32);
    x2[0] = 1;
    memset(z2, 0, 32);
    memcpy(x3, x1, 32);
    memset(z3, 0, 32);
    z3[0] = 1;

    // Montgomery ladder
    for (pos = 254; pos >= 0; --pos) {
        // Get bit from scalar
        unsigned char bit = (scalar[pos / 8] >> (pos & 7)) & 1;
        
        // Conditional swap based on bit
        swap ^= bit;
        
        // Swap points if needed
        for (int i = 0; i < 32; i++) {
            unsigned char dummy = swap & (x2[i] ^ x3[i]);
            x2[i] ^= dummy;
            x3[i] ^= dummy;
            
            dummy = swap & (z2[i] ^ z3[i]);
            z2[i] ^= dummy;
            z3[i] ^= dummy;
        }
        
        swap = bit;
        
        // Point addition and doubling
        // Addition: P2 = P2 + P3, Doubling: P3 = 2*P3
        
        // A = X2 + Z2
        for (int i = 0; i < 32; i++) {
            a[i] = x2[i] + z2[i];
        }
        
        // B = X2 - Z2
        for (int i = 0; i < 32; i++) {
            b[i] = x2[i] - z2[i];
        }
        
        // C = X3 + Z3
        for (int i = 0; i < 32; i++) {
            c[i] = x3[i] + z3[i];
        }
        
        // D = X3 - Z3
        for (int i = 0; i < 32; i++) {
            d[i] = x3[i] - z3[i];
        }
        
        // DA = D * A
        fe_frombytes(t1, d);
        fe_frombytes(t2, a);
        fe_mul(t1, t1, t2);
        fe_tobytes(e, t1);
        
        // CB = C * B
        fe_frombytes(t1, c);
        fe_frombytes(t2, b);
        fe_mul(t1, t1, t2);
        fe_tobytes(f, t1);
        
        // X3 = (DA + CB)^2
        for (int i = 0; i < 32; i++) {
            a[i] = e[i] + f[i];
        }
        fe_frombytes(t1, a);
        fe_sq(t1, t1);
        fe_tobytes(x3, t1);
        
        // Z3 = X1 * (DA - CB)^2
        for (int i = 0; i < 32; i++) {
            a[i] = e[i] - f[i];
        }
        fe_frombytes(t1, a);
        fe_sq(t1, t1);
        fe_frombytes(t2, x1);
        fe_mul(t1, t1, t2);
        fe_tobytes(z3, t1);
        
        // X2 = (A^2) * (B^2)
        fe_frombytes(t1, a);
        fe_sq(t1, t1);
        fe_frombytes(t2, b);
        fe_sq(t2, t2);
        fe_mul(t1, t1, t2);
        fe_tobytes(x2, t1);
        
        // Z2 = (A^2 - B^2) * ((A^2 - B^2) * 121665 + A^2)
        for (int i = 0; i < 32; i++) {
            c[i] = a[i] - b[i];
        }
        for (int i = 0; i < 32; i++) {
            d[i] = a[i] * a[i];
        }
        uint32_t cval = 121665;
        for (int i = 0; i < 32; i++) {
            e[i] = c[i] * cval + d[i];
        }
        fe_frombytes(t1, c);
        fe_frombytes(t2, e);
        fe_mul(t1, t1, t2);
        fe_tobytes(z2, t1);
    }
    
    // Final swap if needed
    for (int i = 0; i < 32; i++) {
        unsigned char dummy = swap & (x2[i] ^ x3[i]);
        x2[i] ^= dummy;
        x3[i] ^= dummy;
        
        dummy = swap & (z2[i] ^ z3[i]);
        z2[i] ^= dummy;
        z3[i] ^= dummy;
    }
    
    // Compute final result X2/Z2
    fe_frombytes(t1, z2);
    fe_invert(zinv, t1);
    fe_frombytes(t1, x2);
    fe_mul(t1, t1, zinv);
    fe_tobytes(q, t1);
}

// Move the fe_cswap definition before its first use in curve25519_scalarmult
static void fe_cswap(fe f, fe g, unsigned int b) {
    b = -b;
    for(int i = 0; i < 16; i++) {
        int64_t t = b & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

// Cryptographically secure random number generation
static int get_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    size_t bytes_read = 0;
    ssize_t result;
    
    // Read in a loop to ensure we get all requested bytes
    while (bytes_read < len) {
        result = read(fd, buf + bytes_read, len - bytes_read);
        if (result <= 0) {
            // Error or EOF
            close(fd);
            return -1;
        }
        bytes_read += result;
    }
    
    close(fd);
    return 0;
}

// Generate a random private key and compute corresponding public key
void curve25519_generate_keypair(key_pair_t *keypair) {
    if (get_random_bytes(keypair->private_key, 32) != 0) {
        // Fallback to time-based seed if /dev/urandom fails
        srand(time(NULL));
        for (int i = 0; i < 32; i++) {
            keypair->private_key[i] = rand() & 0xFF;
        }
    }
    
    // Clamp private key
    keypair->private_key[0] &= 248;
    keypair->private_key[31] &= 127;
    keypair->private_key[31] |= 64;
    
    curve25519_compute_public(keypair->public_key, keypair->private_key);
}

// Compute public key from private key
void curve25519_compute_public(uint8_t *public_key, const uint8_t *private_key) {
    uint8_t private_key_copy[32];
    
    // Copy and ensure private key is properly clamped
    memcpy(private_key_copy, private_key, 32);
    private_key_copy[0] &= 248;
    private_key_copy[31] &= 127;
    private_key_copy[31] |= 64;
    
    // Use base point 9 for X25519
    uint8_t basepoint[32] = {9};
    memset(basepoint + 1, 0, 31);
    
    // Perform scalar multiplication
    curve25519_scalarmult(public_key, private_key_copy, basepoint);
}

void curve25519_shared_secret(uint8_t *shared, const uint8_t *private_key, const uint8_t *public_key) {
    curve25519_scalarmult(shared, private_key, public_key);
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
            
            // Mix in counter
            keystream[0] ^= (i / FIELD_SIZE) & 0xFF;
        }
        
        c[i] = m[i] ^ keystream[i % FIELD_SIZE];
    }
}

// Encrypt file using ECC
int ecc_encrypt(const uint8_t *recipient_public_key, const uint8_t *plaintext, 
                size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len) {
    // Generate ephemeral key pair
    key_pair_t ephemeral;
    if (get_random_bytes(ephemeral.private_key, 32) != 0) {
        fprintf(stderr, "Failed to generate random bytes for key\n");
        return 0;
    }
    
    // Clamp private key
    ephemeral.private_key[0] &= 248;
    ephemeral.private_key[31] &= 127;
    ephemeral.private_key[31] |= 64;
    
    // Compute public key from private key
    curve25519_compute_public(ephemeral.public_key, ephemeral.private_key);
    
    // Compute shared secret
    uint8_t shared_secret[FIELD_SIZE];
    curve25519_shared_secret(shared_secret, ephemeral.private_key, recipient_public_key);
    
    // Allocate ciphertext buffer (ephemeral public key + ciphertext)
    *ciphertext_len = FIELD_SIZE + plaintext_len;
    *ciphertext = (uint8_t *)malloc(*ciphertext_len);
    if (!*ciphertext) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        return 0;
    }
    
    // Copy ephemeral public key to ciphertext
    memcpy(*ciphertext, ephemeral.public_key, FIELD_SIZE);
    
    // Encrypt plaintext
    stream_xor(*ciphertext + FIELD_SIZE, plaintext, plaintext_len, shared_secret);
    
    return 1; // Success
}

// Decrypt file using ECC
int ecc_decrypt(const uint8_t *private_key, const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len) {
    // Check if ciphertext is large enough
    if (ciphertext_len <= FIELD_SIZE) {
        fprintf(stderr, "Ciphertext too short, possibly corrupted\n");
        return 0;
    }
    
    // Extract ephemeral public key
    const uint8_t *ephemeral_public_key = ciphertext;
    
    // Compute shared secret
    uint8_t shared_secret[FIELD_SIZE];
    curve25519_shared_secret(shared_secret, private_key, ephemeral_public_key);
    
    // Calculate plaintext length
    *plaintext_len = ciphertext_len - FIELD_SIZE;
    
    // Allocate plaintext buffer
    *plaintext = (uint8_t *)malloc(*plaintext_len);
    if (!*plaintext) {
        fprintf(stderr, "Memory allocation failed for plaintext\n");
        return 0;
    }
    
    // Decrypt ciphertext
    stream_xor(*plaintext, ciphertext + FIELD_SIZE, *plaintext_len, shared_secret);
    
    return 1; // Success
}

// Read key from file (public for encrypt, private for decrypt)
int read_key(const char *filename, uint8_t *key, crypto_mode_t mode) {
    size_t key_len;
    uint8_t *key_data = read_file(filename, &key_len);
    
    if (mode == MODE_ENCRYPT) {
        // For encryption, we need a public key (32 bytes)
        if (key_len >= FIELD_SIZE) {
            memcpy(key, key_data, FIELD_SIZE);
            free(key_data);
            return 1;
        }
    } else {
        // For decryption, we need a private key (32 bytes)
        if (key_len >= FIELD_SIZE) {
            memcpy(key, key_data, FIELD_SIZE);
            // Ensure proper clamping for Curve25519
            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;
            free(key_data);
            return 1;
        }
    }
    
    free(key_data);
    return 0;
}

// Generate and save a new key pair
void generate_and_save_keypair(const char *filename) {
    key_pair_t keypair;
    curve25519_generate_keypair(&keypair);
    
    // Save both keys to file (64 bytes total)
    write_file(filename, (uint8_t *)&keypair, sizeof(keypair));
    
    printf("Key pair generated and saved to %s\n", filename);
    printf("First 32 bytes: private key\n");
    printf("Last 32 bytes: public key\n");
}
