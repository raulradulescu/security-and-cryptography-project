CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99

SOURCES = tea.c common.c tea_main.c
OBJECTS = $(SOURCES:.c=.o)

all: tea_cbc

tea_cbc: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) tea_cbc *.exe

test:
	@echo "Manual testing instructions:"
	@echo "1. Create a key file: echo 'MySecretKey12345' > key.txt"
	@echo "2. Create test input: echo 'Hello TEA encryption!' > input.txt"
	@echo "3. Encrypt: ./tea_cbc -e -i input.txt -k key.txt -o encrypted.bin"
	@echo "4. Decrypt: ./tea_cbc -d -i encrypted.bin -k key.txt -o decrypted.txt"

.PHONY: all clean test
