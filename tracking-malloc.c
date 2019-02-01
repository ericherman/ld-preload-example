/* tracking-malloc.c: a wrapper for malloc/free
   Copyright (C) 2019 Eric Herman <eric@freesa.org>
   License: LGPL v3 or any later version */

#define _GNU_SOURCE		/* RTLD_NEXT */

#include <stdio.h>		/* FILE printf stderr */
#include <string.h>		/* memcpy memset */
#include <dlfcn.h>		/* dlsym */
#include <unistd.h>		/* write */

/* prototypes */
extern void exit(int status);
extern char *secure_getenv(const char *name);
extern long syscall(long number, ...);

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *reallocarray(void *ptr, size_t nmemb, size_t size);
void free(void *ptr);

/* function pointer types */
typedef void *(*malloc_func)(size_t size);
typedef void *(*calloc_func)(size_t nmemb, size_t size);
typedef void *(*realloc_func)(void *ptr, size_t size);
typedef void *(*reallocarray_func)(void *ptr, size_t nmemb, size_t size);
typedef void (*free_func) (void *ptr);

#define NOP ((void)0)

#if SILENT
#define Log_error3(msg, a, b, c) NOP
#define Log_error5(msg, a, b, c, d, e) NOP
#define Log_msg2(msg, a, b) NOP
#else /* not SILENT */
#define Log_error3(msg, a, b, c) fprintf(stderr, msg, a, b, c)
#define Log_error5(msg, a, b, c, d, e) fprintf(stderr, msg, a, b, c, d, e)
#define Log_msg2(msg, a, b) fprintf(stderr, msg, a, b)
#endif /* SILENT */

#if TRACE
#define trace0(msg) \
	do { \
		write(2, msg, strlen(msg)); \
		write(2, "\n", 1); \
	} while (0)
#else
#define trace0(msg) NOP
#endif

static void *get_func_or_die(const char *file_name, int line_num,
			     const char *func_name, void *wrapper_address)
{
	char *dlerror_msg;
	void *handle;
	void *ptr;

	/* handle = RTLD_DEFAULT; */
	handle = RTLD_NEXT;
	dlerror();
	ptr = dlsym(handle, func_name);
	if ((ptr) && (ptr != wrapper_address)) {
		return ptr;
	}

	if (ptr == wrapper_address) {
		Log_error3("%s:%d dlsym returned the same function for %s\n",
			   file_name, line_num, func_name);
	}

	dlerror_msg = dlerror();
	Log_error5("%s:%d: dlerror: %s, dlsym returned %p for '%s'\n",
		   file_name, line_num, dlerror_msg, ptr, func_name);

	exit(1);
}

#define Get_func_or_die(fname, wrapper) \
	get_func_or_die(__FILE__, __LINE__, fname, wrapper)

static void *get_real_ptr(void *ptr, size_t *size)
{
	unsigned char *real_ptr;

	real_ptr = (unsigned char *)ptr;
	if (ptr) {
		real_ptr = real_ptr - (sizeof(size_t));
		if (size) {
			memcpy(size, real_ptr, sizeof(size_t));
		}
	} else {
		if (size) {
			*size = 0;
		}
	}

	return (void *)real_ptr;
}

static void contidional_track_memory(char v, size_t size)
{
	char *track;

	track = secure_getenv("TRACKING_MALLOC_ENABLE");
	if (track && strlen(track) && track[0] == '1') {
		Log_msg2("%c %lu\n", v, size);
	}
}

void *malloc(size_t size)
{
	malloc_func real_malloc;
	unsigned char *real_ptr;
	void *ptr;
	size_t real_size;

	trace0("malloc");

	if (size == 0) {
		return NULL;
	}

	real_malloc = (malloc_func)Get_func_or_die("malloc", malloc);

	real_size = sizeof(size_t) + size;

	real_ptr = (unsigned char *)(*real_malloc) (real_size);
	if (!real_ptr) {
		return NULL;
	}

	memcpy(real_ptr, &size, sizeof(size_t));

	ptr = (real_ptr + (sizeof(size_t)));

	contidional_track_memory('+', size);

	return ptr;
}

void *memset_calloc(size_t nmemb, size_t size)
{
	void *ptr;

	ptr = malloc(nmemb * size);
	if (ptr) {
		memset(ptr, 0x00, (nmemb * size));
	}

	return ptr;
}

void *calloc(size_t nmemb, size_t size)
{
	calloc_func real_calloc;
	unsigned char *real_ptr;
	size_t real_size;
	void *ptr;

	trace0("calloc");

	if (size == 0) {
		return NULL;
	}

	real_calloc = calloc;
	real_calloc = (calloc_func)Get_func_or_die("calloc", real_calloc);

	real_size = sizeof(size_t) + (nmemb * size);

	real_ptr = (unsigned char *)(*real_calloc) (1, real_size);
	if (!real_ptr) {
		return NULL;
	}

	memcpy(real_ptr, &size, sizeof(size_t));

	ptr = (real_ptr + (sizeof(size_t)));

	contidional_track_memory('+', size);

	return ptr;
}

void *realloc(void *ptr, size_t new_size)
{
	realloc_func real_realloc;
	void *real_old_ptr;
	void *new_ptr;
	unsigned char *real_new_ptr;
	size_t old_size;
	size_t real_new_size;

	trace0("realloc");

	if (new_size == 0) {
		free(ptr);
		return NULL;
	}

	real_realloc = (realloc_func)Get_func_or_die("realloc", realloc);

	if (ptr) {
		real_old_ptr = get_real_ptr(ptr, &old_size);
	} else {
		real_old_ptr = NULL;
		old_size = 0;
	}

	real_new_size = sizeof(size_t) + new_size;

	real_new_ptr =
	    (unsigned char *)(*real_realloc) (real_old_ptr, real_new_size);
	if (!real_new_ptr) {
		return NULL;
	}

	memcpy(real_new_ptr, &new_size, sizeof(size_t));
	if (old_size) {
		contidional_track_memory('-', old_size);
	}
	contidional_track_memory('+', new_size);

	new_ptr = (void *)(real_new_ptr + (sizeof(size_t)));

	return new_ptr;

}

void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	trace0("reallocarray");
	return realloc(ptr, nmemb * size);
}

void free(void *ptr)
{
	free_func real_free;
	void *real_ptr;
	size_t size;

	trace0("free");

	if (ptr == NULL) {
		return;
	}

	real_free = (free_func)Get_func_or_die("free", free);

	real_ptr = get_real_ptr(ptr, &size);

	(*real_free) (real_ptr);

	contidional_track_memory('-', size);
}
