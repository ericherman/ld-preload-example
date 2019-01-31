CC=gcc
CFLAGS=-std=c89 -Wall -Wextra -Werror

default: all

all: demo-dlsym

demo-dlsym: demo-dlsym.c
	$(CC) $(CFLAGS) -o demo-dlsym demo-dlsym.c -ldl

check: demo-dlsym
	./demo-dlsym

valgrind-check:
	valgrind ./demo-dlsym

clean:
	rm -fv ./demo-dlsym
