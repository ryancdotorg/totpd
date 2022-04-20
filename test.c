#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "otp.h"
#include "base32.h"
#include "comm.h"

const int64_t hotp_test_values[][2] = {
  {0, 755224},
  {1, 287082},
  {2, 359152},
  {3, 969429},
  {4, 338314},
  {5, 254676},
  {6, 287922},
  {7, 162583},
  {8, 399871},
  {9, 520489},
  {-1, -1}
};

const int64_t totp_test_values[][4] = {
  {59, 94287082, 46119246, 90693936},
  {1111111109, 7081804, 68084774, 25091201},
  {1111111111, 14050471, 67062674, 99943326},
  {1234567890, 89005924, 91819424, 93441116},
  {2000000000, 69279037, 90698825, 38618901},
  {20000000000ULL, 65353130, 77737706, 47863826},
  {-1, -1, -1, -1}
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int main(int argc, char *argv[]) {
#pragma GCC diagnostic pop
  otp_t h, t1, t256, t512;
  int z, i;

  fprintf(stdout, "hello\n");

  char *k20 = "12345678901234567890";
  char *k32 = "12345678901234567890123456789012";
  char *k64 = "1234567890123456789012345678901234567890123456789012345678901234";

  i = 0;
  printf("HOTP TEST VECTORS\n");
  hotp_init(&h, HASH_SHA1, k20, 20, 6);
  while (hotp_test_values[i][1] >= 0) {
    int c = hotp_test_values[i][0];
    int e = hotp_test_values[i][1];
    int r = hotp(&h, c);
    printf("%d %06d %s %06d\n", c, r, r == e ? "==" : "!=", e);
    ++i;
  }

  i = 0;
  printf("\nTOTP TEST VECTORS\n");
  totp_init(&t1,   HASH_SHA1,   k20, 20, 8, 30);
  totp_init(&t256, HASH_SHA256, k32, 32, 8, 30);
  totp_init(&t512, HASH_SHA512, k64, 64, 8, 30);
  while (totp_test_values[i][1] >= 0) {
    int64_t t = totp_test_values[i][0];
    int a = totp_test_values[i][1];
    int b = totp_test_values[i][2];
    int c = totp_test_values[i][3];
    int ra = totp(&t1, t);
    int rb = totp(&t256, t);
    int rc = totp(&t512, t);
    printf("SHA1   %11ld %08d %s %08d\n", t, ra, ra == a ? "==" : "!=", a);
    printf("SHA256 %11ld %08d %s %08d\n", t, rb, rb == b ? "==" : "!=", b);
    printf("SHA512 %11ld %08d %s %08d\n", t, rc, rc == c ? "==" : "!=", c);
    ++i;
  }
  printf("\n");

  z = totp_verify(&t1, 1234567890,      89005924); printf("verify %d\n", z);
  z = totp_verify(&t1, 1234567890 - 30, 89005924); printf("verify %d\n", z);
  z = totp_verify(&t1, 1234567890 + 30, 89005924); printf("verify %d\n", z);
  z = totp_verify(&t1, 1234567890 - 60, 89005924); printf("verify %d\n", z);
  z = totp_verify(&t1, 1234567890 + 60, 89005924); printf("verify %d\n", z);

  z = totp(&t1, -1); printf("%08d\n", z);
  h.digits = 10;
  z = totp(&t1, -1); printf("%010d\n", z);

  char b32[] = "JBSWY3DPEHPK3PXP";
  for (int q = 1; q < 17; ++q) {
    ssize_t olen;
    unsigned char *key = b32_decode(&olen, b32, q);
    printf("%2d %2zd %p ", q, olen, key);
    for (int i = 0; i < olen; ++i) printf("%02x", key[i]);
    printf("\n");
  }

  ssize_t olen;
  unsigned char *key = b32_decode(&olen, b32, 16);
  totp_init(&t1, HASH_SHA1, key, 10, 6, 30);
  z = totp(&t1, -1);
  printf("%06d\n", z);

  return 0;
}
