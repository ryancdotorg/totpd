#include "config.h"

#include <stdint.h>
#include <stdlib.h>

#include "base32.h"

static uint64_t b32_decode_symbol(ssize_t *olen, uint8_t n)  {
  if (n >= 'A' && n <= 'Z') return n - 65;
  if (n >= 'a' && n <= 'z') return n - 97;
  if (n >= '2' && n <= '7') return n - 24;
  *olen = -1;
  return 0;
}

// This implementation is case insensitive and expects unpadded input. Any
// leftover bits which do not fill a byte will simply be discarded.
uint8_t * b32_decode(ssize_t *olen, const char *str, size_t len) {
  // calculate output size from input size
  *olen = len * 5 >> 3;

  // allocate zero-filled memory to write the result
  uint8_t *ret;
  if ((ret = p_calloc(1, *olen)) == NULL) { return NULL; }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-negative"
// The compiler will optimize out the R == 35 and W >= 0 checks, so there won't
// actually be branches for that code in the binary.
//
// The accum value has bits laid as follows:
//
// 11111222 22333334 44445555 56666677 77788888 (base32 digits)
// 11111111 22222222 33333333 44444444 55555555 (output bytes)
//
// So, we can take output bytes after reading the 2nd, 4th, 5th, 7th and 8th
// base32 digits.
#define DECODE(R, W) \
  if (R == 35) { accum  = b32_decode_symbol(olen, str[i++]) << R; } \
  else {         accum |= b32_decode_symbol(olen, str[i++]) << R; } \
  if (W >= 0) {  ret[p++] = accum >> W; } \
  if (*olen < 0) { return NULL; } else if (i >= len) { return ret; }

  // temporary register for decoding, we use 40 bits of it
  uint64_t accum;
  for (size_t i = 0, p = 0;;) {
    DECODE(35, -1); DECODE(30, 32);
    DECODE(25, -1); DECODE(20, 24);
                    DECODE(15, 16);
    DECODE(10, -1); DECODE( 5,  8);
                    DECODE( 0,  0);
  }
#undef DECODE
#pragma GCC diagnostic pop
}
