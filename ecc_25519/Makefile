CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = 

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
	rm -f $(OBJECTS) $(KEYGEN_OBJECTS) ecc_main keygen

.PHONY: all clean
