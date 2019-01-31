/* tracking-malloc.c: a wrapper for malloc/free
   Copyright (C) 2019 Eric Herman <eric@freesa.org>
   License: LGPL v3 or any later version */

#define _GNU_SOURCE		/* RTLD_NEXT */

#include <stdio.h>		/* FILE printf stderr */
#include <string.h>		/* memcpy */
#include <dlfcn.h>		/* dlsym */

#ifndef TRACKING_MALLOC_STDERR
#define TRACKING_MALLOC_STDERR stderr
#endif

extern void exit(int status);

typedef void *(*malloc_func) (size_t size);
typedef void (*free_func) (void *ptr);

void *get_func_or_die(FILE *err, const char *file_name, int line_num,
		      const char *func_name)
{
	char *dlerror_msg;
	void *handle;
	void *ptr;

	handle = RTLD_NEXT;
	dlerror();
	ptr = dlsym(handle, func_name);
	if (ptr) {
		return ptr;
	}

	dlerror_msg = dlerror();
	fprintf(err, "%s:%d: dlerror: %s, dlsym returned NULL for '%s'\n",
		file_name, line_num, dlerror_msg, func_name);

	exit(1);
}

#define Get_func_or_die(fname) \
	get_func_or_die(TRACKING_MALLOC_STDERR, __FILE__, __LINE__, fname)

void *malloc(size_t size)
{
	malloc_func real_malloc;
	unsigned char *real_ptr;
	unsigned char *ptr;
	size_t real_size;

	real_malloc = (malloc_func) Get_func_or_die("malloc");

	real_size = sizeof(size_t) + size;

	real_ptr = (unsigned char *)(*real_malloc) (real_size);
	if (!real_ptr) {
		return NULL;
	}

	memcpy(real_ptr, &size, sizeof(size_t));
	fprintf(stderr, "+ %lu\n", size);

	ptr = (real_ptr + (sizeof(size_t)));

	return (void *)ptr;

}

void free(void *ptr)
{
	free_func real_free;
	unsigned char *real_ptr;
	size_t size;

	if (ptr == NULL) {
		return;
	}

	real_free = (free_func) Get_func_or_die("free");
	real_ptr = (unsigned char *)ptr;

	real_ptr = real_ptr - (sizeof(size_t));
	memcpy(&size, real_ptr, sizeof(size_t));
	fprintf(stderr, "- %lu\n", size);

	(*real_free) (real_ptr);
}
