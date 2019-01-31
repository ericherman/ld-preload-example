#  Makefile
#  Copyright (C) 2019 Eric Herman <eric@freesa.org>
#  License: LGPL v3 or any later version

CC=gcc
CFLAGS=-std=c89 -g -Wall -Wextra -Werror

default: check

all: \
 demo-dlsym \
 leak \
 tracking-malloc-leak \
 libtracking-malloc.so

demo-dlsym: demo-dlsym.c
	$(CC) $(CFLAGS) -o demo-dlsym demo-dlsym.c -ldl

leak: leak.c
	$(CC) $(CFLAGS) -o leak leak.c

tracking-malloc.o: tracking-malloc.c
	$(CC) -c $(CFLAGS) \
		-o tracking-malloc.o tracking-malloc.c \
		-ldl

tracking-malloc-leak: tracking-malloc.o leak.c
	$(CC) $(CFLAGS) tracking-malloc.o leak.c \
		-o tracking-malloc-leak -ldl

libtracking-malloc.so: tracking-malloc.c
	$(CC) $(CFLAGS) -rdynamic -fPIC -shared \
		-o libtracking-malloc.so tracking-malloc.c \
		-ldl

valgrind: check
	@echo
	valgrind ./leak

check: all
	./demo-dlsym
	./leak
	./tracking-malloc-leak
	LD_LIBRARY_PATH="." LD_PRELOAD=libtracking-malloc.so ./leak

clean:
	rm -fv ./leak ./demo-dlsym ./tracking-malloc-leak *.so *.o
