#  Makefile
#  Copyright (C) 2019 Eric Herman <eric@freesa.org>
#  License: LGPL v3 or any later version

CC=gcc

CFLAGS=-std=c89 -g -Wall -Wextra

ifeq ($(TRACE),1)
CFLAGS += -DTRACE=1
endif

ifeq ($(SILENT),1)
CFLAGS += -DSILENT=1
else
CFLAGS += -Werror
endif

# extracted from https://github.com/torvalds/linux/blob/master/scripts/Lindent
LINDENT=indent -npro -kr -i8 -ts8 -sob -l80 -ss -ncs -cp1 -il0
C_STD_TYPES= -T FILE \
 -T size_t -T ssize_t \
 -T uint8_t -T int8_t \
 -T uint16_t -T int16_t \
 -T uint32_t -T int32_t \
 -T uint64_t -T int64_t
LOCAL_TYPES=-T free_func \
 -T malloc_func -T calloc_func \
 -T realloc_func -T reallocarray_func

default: check

all: \
 demo-dlsym \
 leak \
 tracking-malloc-leak \
 libtracking-malloc.so


# Important symbols:
# $@ : target label (without the colon)
# $< : the first prerequisite after the colon
# $^ : all of the prerequisite files
# $* : wildcard matched part

demo-dlsym: demo-dlsym.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

leak: leak.c
	$(CC) $(CFLAGS) -o $@ $<

tracking-malloc.o: tracking-malloc.c
	$(CC) -c $(CFLAGS) -o $@ $< -ldl

tracking-malloc-leak: tracking-malloc.o leak.c
	$(CC) $(CFLAGS) -o $@ $^ -ldl

libtracking-malloc.so: tracking-malloc.c
	$(CC) $(CFLAGS) -rdynamic -fPIC -shared -o $@ $< -ldl

valgrind: check
	@echo
	valgrind ./leak

check: all no-leak.pl
	./demo-dlsym
	./tracking-malloc-leak
	TRACKING_MALLOC_ENABLE=1 ./tracking-malloc-leak
	./leak
	LD_LIBRARY_PATH="." LD_PRELOAD=libtracking-malloc.so ./leak
	@echo
	TRACKING_MALLOC_ENABLE=1 \
		LD_LIBRARY_PATH="." \
		LD_PRELOAD=libtracking-malloc.so \
		./leak
	@echo
	LD_LIBRARY_PATH="." \
		LD_PRELOAD=libtracking-malloc.so \
		perl ./no-leak.pl

tidy:
	$(LINDENT) $(C_STD_TYPES) $(LOCAL_TYPES) \
	 `find . -name '*.c' -o -name '*.h'`

clean:
	rm -fv ./leak ./demo-dlsym ./tracking-malloc-leak *.so *.o .~
