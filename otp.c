#include "config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <endian.h>
#include <time.h>

#if CRYPTO_ENGINE==openssl
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif

#include "otp.h"

#define _whereami(MSG) fprintf(stderr, "_whereami " MSG " %s:%s:%d\n", __FILE__, __func__, __LINE__)

// this is used to check whether the otp struct is initialized
static uint64_t OTP_MAGIC = 0x60B62708A3E2C313ULL;

static const uint32_t mod[] = {1e6, 1e7, 1e8, 1e9, 0x7fffffff};

static int openssl_hmac_digest(const void *ctx, void *buf, size_t *buf_sz, const void *msg) {
  int rv;
  HMAC_CTX *dctx;
  if ((dctx = HMAC_CTX_new()) == NULL) { return -2; }

  if ((rv = HMAC_CTX_copy(dctx, (HMAC_CTX *)ctx)) != 1) {
    rv = -1; goto openssl_hmac_digest_cleanup;
  }

  if ((rv = HMAC_Update(dctx, (const unsigned char *)msg, 8)) != 1) {
    rv = -1; goto openssl_hmac_digest_cleanup;
  }

  if ((rv = HMAC_Final(dctx, buf, (unsigned int *)buf_sz)) != 1) {
    memset_s(buf, *buf_sz, 0, *buf_sz);
    rv = -1; goto openssl_hmac_digest_cleanup;
  }

  rv = 0;

openssl_hmac_digest_cleanup:
  HMAC_CTX_free(dctx);
  return rv;
}

static void openssl_hmac_free(void *ctx) {
  HMAC_CTX_free((HMAC_CTX *)ctx);
}

static int otp_openssl_init(otp_t *self, hash_algo_t a, const void *secret, size_t len) {
  int rv;

  const EVP_MD *md;
  switch (a) {
    case HASH_SHA1:   md = EVP_sha1();   break;
    case HASH_SHA256: md = EVP_sha256(); break;
    case HASH_SHA512: md = EVP_sha512(); break;
    default: return -1;
  }

  HMAC_CTX *ctx = HMAC_CTX_new();
  if ((rv = HMAC_Init_ex(ctx, secret, len, md, NULL)) != 1) {
    HMAC_CTX_free(ctx);
    return -1;
  }

  self->ctx = ctx;
  self->hmac_digest = &openssl_hmac_digest;
  self->hmac_free = &openssl_hmac_free;

  return 0;
}

static void otp_free(otp_t *self) {
  if (self->magic == OTP_MAGIC) {
    void *p; // stupid hack to prevent warnings about uninitialized values
    memcpy(&p, &(self->ctx), sizeof(void *));
    memcpy(&p, &(self->hmac_free), sizeof(void *));
    self->hmac_free(self->ctx);
  }

  memset_s(self, sizeof(otp_t), 0, sizeof(otp_t));
}

void hotp_free(otp_t *self) { otp_free(self); }
void totp_free(otp_t *self) { otp_free(self); }

static int otp_init(otp_t *self, hash_algo_t a, const void *secret, size_t len, int digits, int timestep) {
  int rv;
  // stupid hack to prevent warnings about uninitialized value
  { uint64_t magic; memcpy(&magic, &(self->magic), sizeof(magic)); }
  // detect whether the structure is already initialized, and if so, free it
  if (self->magic == OTP_MAGIC) { otp_free(self); }
  if (digits < 6 || digits > 10) return -1;

#if CRYPTO_ENGINE==openssl
  rv = otp_openssl_init(self, a, secret, len);
#else
  return -1;
#endif

  if (rv != 0) return rv;

  self->magic = OTP_MAGIC;
  self->digits = digits;
  self->timestep = timestep;

  return 0;
}

int hotp_init(otp_t *self, hash_algo_t a, const void *secret, size_t len, int digits) {
  return otp_init(self, a, secret, len, digits, -1);
}

otp_t * new_hotp(hash_algo_t a, const void *secret, size_t len, int digits) {
  otp_t *self = p_malloc(sizeof(otp_t));
  if (hotp_init(self, a, secret, len, digits) != 0) {
    p_free(self);
    return NULL;
  }
  return self;
}

int totp_init(otp_t *self, hash_algo_t a, const void *secret, size_t len, int digits, int timestep) {
  if (timestep < TIMESTEP_MIN || timestep > TIMESTEP_MAX) return -1;
  return otp_init(self, a, secret, len, digits, timestep);
}

otp_t * new_totp(hash_algo_t a, const void *secret, size_t len, int digits, int timestep) {
  otp_t *self = p_malloc(sizeof(otp_t));
  if (totp_init(self, a, secret, len, digits, timestep) != 0) {
    p_free(self);
    return NULL;
  }
  return self;
}

static int otp(const otp_t *self, const void *msg) {
  int rv = 0;
  uint8_t buf[EVP_MAX_MD_SIZE];
  size_t buf_sz = sizeof(buf);

  if ((rv = self->hmac_digest(self->ctx, buf, &buf_sz, msg)) != 0) {
    return rv;
  }

  uint8_t offset = buf[buf_sz - 1] & 15;
  uint32_t code = (
    (buf[offset] & 127) << 24
    | (buf[offset + 1]) << 16
    | (buf[offset + 2]) << 8
    | buf[offset + 3]
  );

  return code % mod[self->digits - 6];
}

int hotp(const otp_t *self, uint64_t count) {
  count = htobe64(count);
  return otp(self, &count);
}

int hotp_verify(const otp_t *self, uint64_t count, int ref) {
  int v = hotp(self, count);
  if (v < 0) return v;
  return v == ref;
}

int totp(const otp_t *self, int64_t seconds) {
  if (self->timestep <= 0) return -1;
  if (seconds < 0) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return -1;
    seconds = (int64_t)(ts.tv_sec);
  }
  return hotp(self, seconds / self->timestep);
}

int totp_verify(const otp_t *self, int64_t seconds, int ref) {
  int t, result = 0, c = totp(self, seconds);
  if (c < 0) return c;

  t = ref ^ c; // (branchless) t will have non-zero bits unless ref == c
  // (branchless) sets the rightmost bit if any bits set
  t |= t >> 16; t |= t >> 8; t |= t >> 4; t |= t >> 2; t |= t >> 1;
  // (branchless) mask out and invert the rightmost bit
  t = ((t & 1) ^ 1);
  // (branchless) set result bit if this matched
  result |= t << TOTP_CURR_BIT;

  t = ref ^ totp(self, seconds - self->timestep);
  t |= t >> 16; t |= t >> 8; t |= t >> 4; t |= t >> 2; t |= t >> 1;
  t = ((t & 1) ^ 1);
  result |= t << TOTP_PREV_BIT;

  t = ref ^ totp(self, seconds + self->timestep);
  t |= t >> 16; t |= t >> 8; t |= t >> 4; t |= t >> 2; t |= t >> 1;
  t = ((t & 1) ^ 1);
  result |= t << TOTP_NEXT_BIT;

  return result;
}
