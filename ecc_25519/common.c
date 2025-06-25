#include "common.h"

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s (-e|-d) -i <input> -k <key> -o <output>\n", prog);
    exit(EXIT_FAILURE);
}

void parse_cli(int argc, char **argv, cli_args_t *a)
{
    if (argc < 8) usage(argv[0]);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-e")) a->mode = MODE_ENCRYPT;
        else if (!strcmp(argv[i], "-d")) a->mode = MODE_DECRYPT;
        else if (!strcmp(argv[i], "-i")) a->in_fname = argv[++i];
        else if (!strcmp(argv[i], "-k")) a->key_fname = argv[++i];
        else if (!strcmp(argv[i], "-o")) a->out_fname = argv[++i];
        else usage(argv[0]);
    }
    if (!a->in_fname || !a->key_fname || !a->out_fname)
        usage(argv[0]);
}

uint8_t *read_file(const char *fname, size_t *len)
{
    FILE *f = fopen(fname, "rb");
    if (!f) { 
        perror(fname); 
        exit(EXIT_FAILURE); 
    }

    fseek(f, 0, SEEK_END); 
    *len = ftell(f); 
    rewind(f);

    uint8_t *buf = malloc(*len);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    size_t read_bytes = fread(buf, 1, *len, f);
    if (read_bytes != *len) {
        free(buf);
        fclose(f);
        fprintf(stderr, "File read error\n");
        exit(EXIT_FAILURE);
    }
    
    fclose(f);
    return buf;
}

void write_file(const char *fname, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(fname, "wb");
    if (!f) {
        perror(fname); 
        exit(EXIT_FAILURE); 
    }
    fwrite(buf, 1, len, f); 
    fclose(f);
}