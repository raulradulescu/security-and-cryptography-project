#include "common.h"
#include "aes.h"

static void pkcs7_pad(uint8_t **buf, size_t *len)
{
    size_t pad = AES_BLOCK_SIZE - (*len % AES_BLOCK_SIZE);
    if (pad == 0) pad = AES_BLOCK_SIZE;
    *buf = realloc(*buf, *len + pad);
    memset(*buf + *len, (uint8_t)pad, pad);
    *len += pad;
}

static int pkcs7_unpad(uint8_t *buf, size_t *len)
{
    if (*len == 0 || *len % AES_BLOCK_SIZE) return -1;
    uint8_t pad = buf[*len - 1];
    if (pad == 0 || pad > AES_BLOCK_SIZE)   return -1;
    for (size_t i = 1; i <= pad; ++i)
        if (buf[*len - i] != pad) return -1;
    *len -= pad;
    return 0;
}

int main(int argc, char **argv)
{
    cli_args_t a = {0};
    parse_cli(argc, argv, &a);

    /* load key – accept 16/24/32‑byte keys only */
    size_t klen; uint8_t *kbuf = read_file(a.key_fname, &klen);
    if (klen != 16 && klen != 24 && klen != 32) {
        fprintf(stderr, "Key length must be 16, 24 or 32 bytes\n");
        return EXIT_FAILURE;
    }

    /* read input */
    size_t ilen; uint8_t *ibuf = read_file(a.in_fname, &ilen);

    /* prepare key schedule */
    aes_key_t ks;
    aes_key_setup(&ks, kbuf, klen * 8);

    size_t olen = ilen;
    uint8_t *obuf = NULL;

    if (a.mode == MODE_ENCRYPT) {
        pkcs7_pad(&ibuf, &ilen);
        olen = ilen;
    } else if (ilen % AES_BLOCK_SIZE) {
        fprintf(stderr, "Ciphertext length not multiple of 16\n");
        return EXIT_FAILURE;
    }

    obuf = malloc(ilen);

    /* ECB mode – **not** secure for real‑world data, but matches your CLI skeleton */
    for (size_t off = 0; off < ilen; off += AES_BLOCK_SIZE) {
        if (a.mode == MODE_ENCRYPT)
            aes_encrypt_block(&ks, ibuf + off, obuf + off);
        else
            aes_decrypt_block(&ks, ibuf + off, obuf + off);
    }

    if (a.mode == MODE_DECRYPT) {
        if (pkcs7_unpad(obuf, &olen) != 0) {
            fprintf(stderr, "Bad padding – wrong key or tampered data?\n");
            return EXIT_FAILURE;
        }
    }

    write_file(a.out_fname, obuf, olen);
    free(kbuf); free(ibuf); free(obuf);
    return EXIT_SUCCESS;
}
