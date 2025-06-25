/* driver.c – AES‑CBC encrypt/decrypt tool
 *
 *   encrypt: aes_tool -e -i plain.bin  -k key.bin -o secret.bin
 *   decrypt: aes_tool -d -i secret.bin -k key.bin -o plain.bin
 *
 * The IV is chosen at random when encrypting and stored as the first
 * 16 bytes of the ciphertext file.  Decrypt simply reads it back.
 *
 */
#include "common.h"
#include "aes.h"
#include <fcntl.h>
#include <unistd.h>

#define IV_BYTES 16

/* ---------- PKCS#7 helpers -------------------------------------------- */
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

/* ---------- Random IV -------------------------------------------------- */
static void random_bytes(uint8_t *dst, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, dst, n) != (ssize_t)n) {
        perror("/dev/urandom"); exit(EXIT_FAILURE);
    }
    close(fd);
}

/* ---------- CBC core --------------------------------------------------- */
static void cbc_encrypt(uint8_t *buf, size_t len,
                        const aes_key_t *ks, const uint8_t iv[16])
{
    uint8_t chain[16];
    memcpy(chain, iv, 16);

    for (size_t off = 0; off < len; off += AES_BLOCK_SIZE) {
        for (int i = 0; i < 16; ++i) buf[off + i] ^= chain[i];
        aes_encrypt_block(ks, buf + off, buf + off);
        memcpy(chain, buf + off, 16);
    }
}

static void cbc_decrypt(uint8_t *buf, size_t len,
                        const aes_key_t *ks, const uint8_t iv[16])
{
    uint8_t chain[16], next_chain[16];
    memcpy(chain, iv, 16);

    for (size_t off = 0; off < len; off += AES_BLOCK_SIZE) {
        memcpy(next_chain, buf + off, 16);
        aes_decrypt_block(ks, buf + off, buf + off);
        for (int i = 0; i < 16; ++i) buf[off + i] ^= chain[i];
        memcpy(chain, next_chain, 16);
    }
}

/* ---------- main ------------------------------------------------------- */
int main(int argc, char **argv)
{
    cli_args_t a = {0};
    parse_cli(argc, argv, &a);

    /* --- key ----------------------------------------------------------- */
    size_t klen; uint8_t *kbuf = read_file(a.key_fname, &klen);
    if (klen != 16 && klen != 24 && klen != 32) {
        fprintf(stderr, "Key length must be 16, 24 or 32 bytes\n");
        return EXIT_FAILURE;
    }
    aes_key_t ks;
    aes_key_setup(&ks, kbuf, klen * 8);

    /* ------------------------------------------------------------------- */
    if (a.mode == MODE_ENCRYPT) {
        size_t ilen; uint8_t *ibuf = read_file(a.in_fname, &ilen);
        pkcs7_pad(&ibuf, &ilen);

        uint8_t iv[IV_BYTES];
        random_bytes(iv, IV_BYTES);
        cbc_encrypt(ibuf, ilen, &ks, iv);

        /* IV ⧺ ciphertext */
        FILE *out = fopen(a.out_fname, "wb");
        if (!out) { perror(a.out_fname); exit(EXIT_FAILURE); }
        fwrite(iv, 1, IV_BYTES, out);
        fwrite(ibuf, 1, ilen, out);
        fclose(out);
        free(ibuf);
    } else { /* MODE_DECRYPT */
        size_t clen; uint8_t *cbuf = read_file(a.in_fname, &clen);
        if (clen < IV_BYTES || (clen - IV_BYTES) % AES_BLOCK_SIZE) {
            fprintf(stderr, "Ciphertext length invalid\n");
            return EXIT_FAILURE;
        }
        uint8_t iv[IV_BYTES];
        memcpy(iv, cbuf, IV_BYTES);
        uint8_t *pbuf = cbuf + IV_BYTES;
        size_t  plen = clen - IV_BYTES;

        cbc_decrypt(pbuf, plen, &ks, iv);
        if (pkcs7_unpad(pbuf, &plen) != 0) {
            fprintf(stderr, "Bad padding — wrong key or tampered data?\n");
            return EXIT_FAILURE;
        }
        write_file(a.out_fname, pbuf, plen);
        free(cbuf); /* frees both buffers, since pbuf is inside cbuf */
    }

    free(kbuf);
    return EXIT_SUCCESS;
}
