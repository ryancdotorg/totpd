#pragma once
typedef enum {
  CMD_CLOSE           =   'Q',
  CMD_PING            =   'P',
  REPLY_PING          =   'p',
  CMD_ADD_SECRET      =   'A',
  REPLY_ADD_SECRET    =   'a',
  CMD_CLEAR_SECRET    =   'C',
  REPLY_CLEAR_SECRET  =   'c',
  CMD_GENERATE_TOTP   =   'G',
  REPLY_GENERATE_TOTP =   'g',
  CMD_VERIFY_TOTP     =   'V',
  REPLY_VERIFY_TOTP   =   'v',
  REPLY_ERROR         =   'E',
} type_t;

typedef enum {
  TLV_IDLE,
  TLV_READING,
  TLV_WRITING,
  TLV_INVALID,
} state_t;

#define TLV_BUF_SZ 257

typedef struct {
  int fd;
  int pos;
  int fill;
  state_t state;
  unsigned char buf[TLV_BUF_SZ];
} tlv_ctx;

void tlv_init(tlv_ctx *ctx, int fd);
int tlv_write_continue(tlv_ctx *ctx);
int tlv_read(tlv_ctx *ctx, int *type, int *length, void *value);
int tlv_write(tlv_ctx *ctx, struct pollfd *pfd, type_t type, uint8_t length, const void *value);
