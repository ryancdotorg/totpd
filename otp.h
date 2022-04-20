#pragma once

#define TIMESTEP_MIN   1
#define TIMESTEP_MAX 300

typedef enum {
  HASH_SHA1, HASH_SHA256, HASH_SHA512
} hash_algo_t;

#define TOTP_FAIL 0;

#define TOTP_CURR_BIT 0
#define TOTP_CURR (1<<TOTP_CURR_BIT);
#define TOTP_PREV_BIT 1
#define TOTP_PREV (1<<TOTP_PREV_BIT);
#define TOTP_NEXT_BIT 2
#define TOTP_NEXT (1<<TOTP_NEXT_BIT);

typedef int (hmac_digest_t)(const void *ctx, void *buf, size_t *buf_sz, const void *msg);
typedef void (hmac_free_t)(void *ctx);

typedef struct otp_s {
  uint64_t      magic;
  hmac_digest_t *hmac_digest;
  hmac_free_t   *hmac_free;
  void          *ctx;
  int           digits;
  int           timestep;
} otp_t;

void hotp_free(otp_t *otp);
otp_t * new_hotp(hash_algo_t a, const void *secret, size_t len, int digits);
int hotp_init(otp_t *otp, hash_algo_t a, const void *secret, size_t len, int digits);
int hotp(const otp_t *self, uint64_t count);
int hotp_verify(const otp_t *self, uint64_t count, int ref);

void totp_free(otp_t *otp);
otp_t * new_totp(hash_algo_t a, const void *secret, size_t len, int digits, int timestep);
int totp_init(otp_t *otp, hash_algo_t a, const void *secret, size_t len, int digits, int timestep);
int totp(const otp_t *self, int64_t seconds);
int totp_verify(const otp_t *self, int64_t seconds, int ref);
