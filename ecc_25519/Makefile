CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99

SOURCES = curve25519.c common.c ecc_main.c
KEYGEN_SOURCES = curve25519.c common.c keygen.c

OBJECTS = $(SOURCES:.c=.o)
KEYGEN_OBJECTS = $(KEYGEN_SOURCES:.c=.o)

all: ecc_main keygen

ecc_main: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

keygen: $(KEYGEN_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(KEYGEN_OBJECTS) ecc_main keygen *.exe

test:
	@echo "Manual testing instructions:"
	@echo "1. Generate keys: ./keygen test"
	@echo "2. Encrypt: ./ecc_main -e -i input.txt -k test -o output.enc"
	@echo "3. Decrypt: ./ecc_main -d -i output.enc -k test -o decrypted.txt"

.PHONY: all clean test
