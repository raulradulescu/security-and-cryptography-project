CC := gcc
CFLAGS := -std=c99 -Wall -Wextra -O2
SRCS := aes.c common.c driver_aes_CBC.c
HDRS := aes.h common.h
OBJS := $(SRCS:.c=.o)
TARGET := aes_cbc

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean