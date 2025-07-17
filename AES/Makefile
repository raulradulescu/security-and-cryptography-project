CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99

# CBC mode (recommended)
CBC_SOURCES = aes.c common.c driver_aes_CBC.c
CBC_OBJECTS = $(CBC_SOURCES:.c=.o)

# ECB mode (for demonstration only)
ECB_SOURCES = aes.c common.c driver_aes_ECB.c
ECB_OBJECTS = $(ECB_SOURCES:.c=.o)

all: aes_cbc aes_ecb

aes_cbc: $(CBC_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

aes_ecb: $(ECB_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(CBC_OBJECTS) $(ECB_OBJECTS) aes_cbc aes_ecb *.exe

test:
	@echo "Manual testing instructions for AES:"
	@echo "1. Create a key file (16/24/32 bytes):"
	@echo "   echo 'MySecretKey12345' > key.txt        # 16-byte key for AES-128"
	@echo "   echo 'MySecretKey123456789012345' > key.txt  # 24-byte key for AES-192"
	@echo "2. Create test input:"
	@echo "   echo 'Hello AES encryption!' > input.txt"
	@echo "3. Encrypt (CBC mode - recommended):"
	@echo "   ./aes_cbc -e -i input.txt -k key.txt -o encrypted.bin"
	@echo "4. Decrypt (CBC mode):"
	@echo "   ./aes_cbc -d -i encrypted.bin -k key.txt -o decrypted.txt"
	@echo "5. For ECB mode (less secure):"
	@echo "   ./aes_ecb -e -i input.txt -k key.txt -o encrypted_ecb.bin"
	@echo "   ./aes_ecb -d -i encrypted_ecb.bin -k key.txt -o decrypted_ecb.txt"

.PHONY: all clean test