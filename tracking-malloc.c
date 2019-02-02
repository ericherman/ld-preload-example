/* tracking-malloc.c: a wrapper for malloc/free
   Copyright (C) 2019 Eric Herman <eric@freesa.org>
   License: LGPL v3 or any later version */

#define _GNU_SOURCE		/* RTLD_NEXT */

#include <stdio.h>		/* snprintf */
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

/* global variables */
malloc_func real_malloc;
calloc_func real_calloc;
realloc_func real_realloc;
free_func real_free;

/* In a few situations dlsym can allocate a byte or a small buffer
 * to avoid issues with recursion, reserve a few static bytes for
 * use for this. Should this turn out to be insufficient, it can
 * be made more real. At the moment, the program simply exits if
 * more than a total of 1k is allocated by dlsym. */
unsigned char dlsym_recursion_avoidance_buffer[1024];
const size_t Dlsym_recursion_avoidance_buffer_len = 1024;
size_t dlsym_recursion_avoidance_buffer_used = 0;

#define NOP ((void)0)

#if SILENT
#define Log_error0(buf);
#define Log_error3(buf, len, msg, a, b, c) NOP
#define Log_error5(buf, len, msg, a, b, c, d, e) NOP
#define Log_msg2(buf, len, msg, a, b) NOP
#else /* not SILENT */
#define Log_error0(buf) write(2, buf, strlen(buf))
#define Log_error3(buf, len, msg, a, b, c) do { \
		snprintf(buf, len, msg, a, b, c); \
		write(2, buf, strlen(buf)); \
	} while (0)
#define Log_error5(buf, len, msg, a, b, c, d, e) do { \
		snprintf(buf, len, msg, a, b, c, d, e); \
		write(2, buf, strlen(buf)); \
	} while (0)
#define Log_msg2(buf, len, msg, a, b) do { \
		snprintf(buf, len, msg, a, b); \
		write(2, buf, strlen(buf)); \
	} while (0)
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

static void *get_func_or_die(const char *file_name, int line_num, int first,
			     const char *func_name, void *wrapper_address)
{
	char *dlerror_msg;
	void *handle;
	void *ptr;
	char buf[80];

	handle = (first) ? RTLD_DEFAULT : RTLD_NEXT;
	dlerror();
	ptr = dlsym(handle, func_name);
	if ((ptr) && (ptr != wrapper_address)) {
		return ptr;
	}

	if (ptr == wrapper_address) {
		Log_error3(buf, 80,
			   "%s:%d dlsym returned the same function for %s\n",
			   file_name, line_num, func_name);
	}
	dlerror_msg = dlerror();
	Log_error5(buf, 80, "%s:%d: dlerror: %s, dlsym returned %p for '%s'\n",
		   file_name, line_num, dlerror_msg, ptr, func_name);

	exit(1);
}

#define Get_func_or_die(first, fname, wrapper) \
	get_func_or_die(__FILE__, __LINE__, first, fname, wrapper)

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
	char buf[40];
	char *track;

	track = secure_getenv("TRACKING_MALLOC_ENABLE");
	if (track && strlen(track) && track[0] == '1') {
		Log_msg2(buf, 40, "%c %lu\n", v, size);
	}
}

void *malloc(size_t size)
{
	static int inside_dlsym = 0;
	unsigned char *real_ptr;
	void *ptr;
	size_t real_size;

	trace0("malloc");

	if (size == 0) {
		return NULL;
	}

	if (!real_malloc) {
		if (!inside_dlsym) {
			inside_dlsym = 1;
			real_malloc =
			    (malloc_func)Get_func_or_die(0, "malloc", malloc);
		} else {
			dlsym_recursion_avoidance_buffer_used += size;
			if (dlsym_recursion_avoidance_buffer_used >
			    Dlsym_recursion_avoidance_buffer_len) {
				exit(1);
			}

			ptr =
			    (void *)(dlsym_recursion_avoidance_buffer +
				     dlsym_recursion_avoidance_buffer_used);

			return ptr;
		}
	}

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
	static int inside_dlsym = 0;
	unsigned char *real_ptr;
	size_t real_size;
	void *ptr;

	trace0("calloc");

	if (size == 0) {
		return NULL;
	}

	if (!real_calloc) {
		if (!inside_dlsym) {
			inside_dlsym = 1;
			real_calloc =
			    (calloc_func)Get_func_or_die(0, "calloc", calloc);
		} else {
			dlsym_recursion_avoidance_buffer_used += size;
			if (dlsym_recursion_avoidance_buffer_used >
			    Dlsym_recursion_avoidance_buffer_len) {
				exit(1);
			}

			ptr =
			    (void *)(dlsym_recursion_avoidance_buffer +
				     dlsym_recursion_avoidance_buffer_used);

			memset(ptr, 0x00, size);
			return ptr;
		}
	}

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
	static int inside_dlsym = 0;
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

	if (!real_realloc) {
		if (!inside_dlsym) {
			inside_dlsym = 1;
			real_realloc =
			    (realloc_func)Get_func_or_die(0, "realloc",
							  realloc);
		} else {
			Log_error0("realloc recursion?\n");
			exit(0);
		}
	}

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

static int inside_dlsym_recursion_avoidance_buffer(void *ptr)
{
	unsigned long lptr, lbuf, lbuf_max;

	lptr = (unsigned long)ptr;
	lbuf = (unsigned long)dlsym_recursion_avoidance_buffer;
	lbuf_max = lbuf + Dlsym_recursion_avoidance_buffer_len;

	if ((lptr >= lbuf) && (lptr < lbuf_max)) {
		return 1;
	}

	return 0;
}

void free(void *ptr)
{
	void *real_ptr;
	size_t size;

	trace0("free");

	if (ptr == NULL) {
		return;
	}
	if (inside_dlsym_recursion_avoidance_buffer(ptr)) {
		/* ignore it */
		return;
	}

	if (!real_free) {
		real_free = (free_func)Get_func_or_die(0, "free", free);
	}

	real_ptr = get_real_ptr(ptr, &size);

	(*real_free) (real_ptr);

	contidional_track_memory('-', size);
}
