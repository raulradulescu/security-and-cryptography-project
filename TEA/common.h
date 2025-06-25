#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { MODE_ENCRYPT, MODE_DECRYPT } crypto_mode_t;

typedef struct {
    crypto_mode_t mode;
    const char *in_fname;
    const char *key_fname;
    const char *out_fname;
} cli_args_t;

void parse_cli(int argc, char **argv, cli_args_t *args);
uint8_t *read_file(const char *fname, size_t *len);
void     write_file(const char *fname, const uint8_t *buf, size_t len);

#endif