#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "comm.h"

void tlv_init(tlv_ctx *ctx, int fd) {
  memset_s(ctx, sizeof(tlv_ctx), 0, sizeof(tlv_ctx));
  ctx->state = TLV_IDLE;
  ctx->fd = fd;
}

int tlv_write_continue(tlv_ctx *ctx) {
  ssize_t ret;

  // validate state
  if (ctx->state != TLV_WRITING) {
    errno = ENOTRECOVERABLE;
    ret = -1;
    goto tlv_write_continue_abort;
  }

  int remain = ctx->fill - ctx->pos;

  // write and update buffer status
  if ((ret = write(ctx->fd, ctx->buf + ctx->pos, remain)) != remain) {
    if (ret > 0) {
      ctx->pos += ret;
      errno = EAGAIN;
      ret = -2;
    }
    goto tlv_write_continue_abort;
  } else {
    ctx->pos += ret;
  }

  // we're done if the whole buffer's been written out
  if (ctx->pos == ctx->fill) {
    ret = ctx->buf[1];
    tlv_init(ctx, ctx->fd);
    return 0;
  }

tlv_write_continue_abort:
  if (ret <= 0 && errno != EAGAIN) {
    // close socket and wipe buffer on failure
    close(ctx->fd);
    tlv_init(ctx, -1);
  }
  return ret;
}

int tlv_write(tlv_ctx *ctx, struct pollfd *pfd, type_t type, uint8_t length, const void *value) {
  // set up the struct for writing but don't actually try to write
  if (ctx->state == TLV_IDLE) {
    ctx->buf[0] = type;
    ctx->buf[1] = length;
    memcpy(ctx->buf + 2, value, length);
    ctx->fill = 2 + length;
    ctx->pos = 0;

    ctx->state = TLV_WRITING;
    pfd->events |= POLLOUT;
  } else {
    errno = ENOTRECOVERABLE;
    return -1;
  }

  return 0;
}

int tlv_read(tlv_ctx *ctx, int *type, int *length, void *value) {
  ssize_t ret;

  // validate state
  if (!(ctx->state == TLV_IDLE || ctx->state == TLV_READING)) {
    errno = ENOTRECOVERABLE;
    ret = -1;
    goto tlv_read_abort;
  }

  ctx->state = TLV_READING;

  // keep writing until we fail or are done
  for (int remain = 1; remain > 0; ctx->fill += ret) {
    // figure out how much we need to read
    if (ctx->fill < 2) {
      // we need to read the header
      remain = 2 - ctx->fill;
    } else {
      // we need to read the data
      remain = ctx->buf[1] - (ctx->fill - 2);
    }

    // try to read
    if ((ret = read(ctx->fd, ctx->buf + ctx->fill, remain)) != remain) {
      if (ret > 0) {
        // no error, but we don't yet have a full message
        ctx->fill += ret;
        errno = EAGAIN;
        ret = -2;
      }
      goto tlv_read_abort;
    }
  }

  // save results
  *type = ctx->buf[0];
  *length = ctx->buf[1];
  memcpy(value, ctx->buf + 2, *length);

  // clear buffer and return success
  tlv_init(ctx, ctx->fd);
  return 1;

tlv_read_abort:
  if (ret <= 0 && errno != EAGAIN) {
    // close socket and wipe buffer on failure
    close(ctx->fd);
    tlv_init(ctx, -1);
  }
  return ret;
}
