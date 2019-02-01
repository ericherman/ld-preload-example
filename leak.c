/* leak.c: a program which leaks memory
   Copyright (C) 2019 Eric Herman <eric@freesa.org>
   License: LGPL v3 or any later version */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	void *ptr;
	unsigned i, goods, leaks;
	size_t size;

	leaks = (argc > 1) ? (unsigned)atoi(argv[1]) : 1;
	goods = (argc > 2) ? (unsigned)atoi(argv[2]) : 2;
	size = (argc > 3) ? (unsigned)atoi(argv[3]) : 42;

	for (i = 0; i < leaks; ++i) {
		ptr = malloc(0);
		ptr = realloc(ptr, size);
		ptr = realloc(ptr, size * (i + 3));
		if (size > i) {
			ptr = realloc(ptr, size - i);
		}
	}
	for (i = 0; i < goods; ++i) {
		ptr = calloc(2, size + i);
		free(ptr);
	}
	return 0;
}
