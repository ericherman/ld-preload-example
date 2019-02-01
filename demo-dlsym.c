/* demo-dlsym.c: example of using dlsym
   Copyright (C) 2019 Eric Herman <eric@freesa.org>
   License: LGPL v3 or any later version */

#include <stdio.h>		/* fprintf stderr */
#include <dlfcn.h>		/* dlsym */
extern void exit(int status);
extern int atoi(const char *nptr);

void *get_func_or_die(const char *func_name)
{
	char *dlerror_msg;
	void *handle;
	void *ptr;

	handle = NULL;
	dlerror();
	ptr = dlsym(handle, func_name);
	if (ptr) {
		return ptr;
	}

	dlerror_msg = dlerror();
	fprintf(stderr, "dlerror: %s, dlsym returned NULL for '%s'\n",
		dlerror_msg, func_name);
	exit(1);
}

typedef void *(*malloc_func)(size_t size);
typedef void (*free_func) (void *ptr);

int main(int argc, char **argv)
{
	void *ptr;
	size_t size;
	malloc_func real_malloc;
	free_func real_free;

	size = (argc > 1) ? (unsigned)atoi(argv[1]) : sizeof(void *);

	real_malloc = (malloc_func)get_func_or_die("malloc");

	ptr = (*real_malloc) (size);
	printf("real_malloc returned %p for size: %lu\n", ptr, size);
	if (!ptr) {
		return 1;
	}

	real_free = (free_func)get_func_or_die("free");
	(*real_free) (ptr);
	printf("real_free complete\n");

	return 0;
}
