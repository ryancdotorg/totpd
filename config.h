#pragma once
#define __STDC_WANT_LIB_EXT1__ 1
#define _DEFAULT_SOURCE

#include <stddef.h>

#ifndef CRYPTO_ENGINE
#define CRYPTO_ENGINE openssl
#endif//CRYPTO_ENGINE

#ifndef NDEBUG

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#define debugf(E, ...) _debugf((E), __FILE__, __func__, __LINE__, __VA_ARGS__)
static void _debugf(int err, const char *file, const char *func, int line, ...) {
  int fmtlen, nl = 0, errsv = errno;
  va_list args;
  va_start(args, line);

  // handle format spec
  const char *srcfmt = va_arg(args, const char *);
  char fmt[256];
  strncpy(fmt, srcfmt, sizeof(fmt));
  fmt[sizeof(fmt)-1] = 0;
  if ((fmtlen = strlen(fmt)) > 0 && fmt[fmtlen-1] == '\n') {
    nl = 1; fmt[--fmtlen] = 0;
  }

  // print passed data formatted as specified to stderr
  vdprintf(2, fmt, args);

  // print extra stuff
  if (err) dprintf(2, ": %s (err=%d)", strerror(err), err);
  if (nl) {
    if (func != NULL) {
      dprintf(2, " [%s:%s:%d]\n", file, func, line);
    } else {
      dprintf(2, " [%s:%d]\n", file, line);
    }
  }
  errno = errsv;
}
#else
#define debugf(E, ...) ()
#endif

#ifndef __STDC_LIB_EXT1__
int memset_s(void *v, size_t smax, int c, size_t n);
#endif

int lock_mem(void *str, size_t num);
// trigger _memlook_hook to run at program start
void __attribute__((constructor)) _memlock_hook(void);

void p_free(void *str);
void * p_malloc(size_t num);
void * p_calloc(size_t num, size_t count);
void * p_realloc(void *str, size_t num);
void * p_reallocarray(void *str, size_t num, size_t count);
