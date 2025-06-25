CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99

all: tea_cbc

tea_cbc: tea_main.o tea.o common.o
	$(CC) $(CFLAGS) -o tea_cbc $^

tea_main.o: tea_main.c tea.h common.h
	$(CC) $(CFLAGS) -c tea_main.c -o tea_main.o

tea.o: tea.c tea.h
	$(CC) $(CFLAGS) -c tea.c -o tea.o

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c -o common.o

clean:
	rm -f tea_cbc *.o

.PHONY: all clean
