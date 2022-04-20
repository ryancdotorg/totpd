#include "config.h"

#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <sys/mman.h>

#if CRYPTO_ENGINE==openssl
#include <openssl/crypto.h>
#endif

#ifndef __STDC_LIB_EXT1__
__attribute__((weak)) void __dont_optimize_me(void *v, size_t n) {}
int memset_s(void *v, size_t smax, int c, size_t n) {
  if (v == NULL || n > smax) return EINVAL;
  volatile unsigned char *p = v;
  while (n--) *p++ = c;
  /* try very hard to prevent the compiler from optimizing this out */
  __asm__("" ::: "memory");
  __dont_optimize_me(v, n);
  return 0;
}
#endif

static int memready = 0;
#define ptrsize sizeof(void *)
static unsigned int pagesize;

static void * alignceil(void *ptr, size_t m) {
  // rounds pointer up to an increment on m
  // if pointer is already an increment of m, it won't change
  return (void *)( ((uintptr_t)ptr + m - 1) & (-m) );
}

static void * alignfloor(void *ptr, size_t m) {
  // rounds pointer down to an increment on m
  // if pointer is already an increment of m, it won't change
  return (void *)( (uintptr_t)ptr & (-m) );
}

// pointer arithmatic functions
static void * padd(void *p, size_t n) { return (void *)((uint8_t *)p + n); }
static void * psub(void *p, size_t n) { return (void *)((uint8_t *)p - n); }
static ptrdiff_t pdiff(void *a, void *b) { return (uint8_t *)a - (uint8_t *)b; }

int lock_mem(void *str, size_t num) {
  if (num == 0) return 0;

  // limit how much we repeatedly try to lock the same regions
  static void *last_page_start = NULL;
  static size_t last_page_size = 0;

  void *page_start = alignfloor(str, pagesize);
  size_t page_size = pdiff(alignceil(padd(str, num), pagesize), page_start);

  // mlock/madvise may fail if arguments are not page aligned
  if (page_start == last_page_start && page_size == last_page_size) {
    return 0;
  } else {
    last_page_start = page_start;
    last_page_size = page_size;
  }

  // prevent swapping
  if (mlock(str, num) != 0) {
    fprintf(stderr, "mlock failed %zu @ %p: %s (%d)\n", num, str, strerror(errno), errno);
    return -1;
  }

  // prevent inclusion in core dumps
  if (madvise(page_start, page_size, MADV_DONTDUMP) != 0) {
    fprintf(stderr, "madvise failed %zu @ %p: %s (%d)\n", num, str, strerror(errno), errno);
    return -1;
  }

  return 0;
}

// Wrapper functions that implement "fat pointers" which place information
// about the allocation size immediately before the pointer value.
// Additionally, all allocated memory is locked to prevent it from being
// inadvertently written to disk.

// TODO Maybe register an atexit to free everything here

// free a fat pointer
void p_free(void *str) {
  size_t sz = *((size_t *)psub(str, sizeof(size_t)));
  memset_s(str, sz, 0, sz);
  free(psub(str, sizeof(size_t)));
}

// malloc and lock a fat pointer
void * p_malloc(size_t num) {
  void *str = malloc(num+sizeof(size_t));
  memcpy(str, &num, sizeof(size_t));
  lock_mem(str, num);
  return padd(str, sizeof(size_t));
}

// calloc and lock a fat pointer
void * p_calloc(size_t num, size_t count) {
  size_t size = num * count;
  if (num != 0 && size / num != count) return NULL;
  void *str = p_malloc(size);
  // calloc returns zero'd memory
  if (str != NULL) { memset_s(str, num, 0, num); }
  return str;
}

// this replaces realloc with malloc/copy/wipe
void * p_realloc(void *str, size_t num) {
  void *ret = p_malloc(num);
  size_t sz = *((size_t *)psub(str, sizeof(size_t)));
  memcpy(ret, str, sz < num ? sz : num);
  memset_s(str, sz, 0, sz);
  return ret;
}

// this replaces reallocarray with malloc/copy/wipe
void * p_reallocarray(void *str, size_t num, size_t count) {
  void *ret = p_calloc(num, count);
  if (ret == NULL) return NULL;
  size_t sz = *((size_t *)psub(str, sizeof(size_t)));
  memcpy(ret, str, sz < num ? sz : num);
  memset_s(str, sz, 0, sz);
  return ret;
}

// wrappers for openssl
static void _wrap_free(void *str, const char *file, int line) {
  p_free(str);
  //_debugf(0, file, NULL, line, "free(%p)\n", str);
}

static void * _wrap_malloc(size_t num, const char *file, int line) {
  void *str = p_malloc(num);
  //_debugf(0, file, NULL, line, "malloc(%zu) -> %p\n", num, str);
  return str;
}

static void * _wrap_realloc(void *str, size_t num, const char *file, int line) {
  void *ret = p_realloc(str, num);
  //_debugf(0, file, NULL, line, "realloc(%p, %zu) -> %p\n", str, num, ret);
  return ret;
}

void _memlock_hook() {
  if (memready) return;
  pagesize = sysconf(_SC_PAGESIZE);

#if CRYPTO_ENGINE==openssl
  CRYPTO_set_mem_functions(_wrap_malloc, _wrap_realloc, _wrap_free);
#endif

  memready = 1;
}
