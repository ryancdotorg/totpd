#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/random.h>

#include <systemd/sd-daemon.h>

#include "otp.h"
#include "comm.h"
#include "base32.h"

#include "uthash.h"

typedef struct {
  unsigned char id[32];
  otp_t *otp;
  UT_hash_handle hh;
} otp_ht;

typedef struct {
  int first_listener;
  int last_listener;
  int num_clients;
  int max_clients;
  struct pollfd *pfds;
  tlv_ctx *tlvs;
} sock_ctx;

int socket_init(sock_ctx *ctx, int num_listeners, int first_listener) {
  // init the simple values
  if (num_listeners == 0) {
    ctx->first_listener = ctx->last_listener = -1;
  } else {
    ctx->first_listener = first_listener;
    ctx->last_listener = first_listener + num_listeners;
  }
  ctx->num_clients = 0;
  ctx->max_clients = 2;

  // allocate listener array
  if ((ctx->pfds = calloc(ctx->max_clients + num_listeners, sizeof(*(ctx->pfds)))) == NULL) {
    return -1;
  }

  // set up the listeners
  for (int i = 0; i < num_listeners; ++i) {
    ctx->pfds[i].fd = i + first_listener;
    ctx->pfds[i].events = POLLIN;
  }

  // allocate tlv context array
  if ((ctx->tlvs = p_calloc(ctx->max_clients, sizeof(*(ctx->tlvs)))) == NULL) {
    return -1;
  }

  return 0;
}

int client_add(sock_ctx *ctx, int newfd) {
  int num_listeners = ctx->last_listener - ctx->first_listener;

  // expand arrays if full
  if (ctx->num_clients == ctx->max_clients) {
    // double max elements
    ctx->max_clients *= 2;

    // allocate a new tlv context array
    if ((ctx->tlvs = p_reallocarray(ctx->tlvs, ctx->max_clients, sizeof(*(ctx->tlvs)))) == NULL) {
      return -1;
    }

    // event stuff is easy
    int new_pfds = num_listeners + ctx->max_clients;
    ctx->pfds = reallocarray(ctx->pfds, new_pfds, sizeof(*(ctx->pfds)));
    if (ctx->pfds == NULL) {
      // wipe the tlv context array
      int tlvs_size = ctx->max_clients * sizeof(*(ctx->tlvs));
      memset_s(ctx->tlvs, tlvs_size, 0, tlvs_size);
      return -1;
    }
  }

  // there are potentially more entries in pfds than tlvs due to listeners
  ctx->pfds[num_listeners + ctx->num_clients].fd = newfd;
  ctx->pfds[num_listeners + ctx->num_clients].events = POLLIN;
  tlv_init(&(ctx->tlvs[ctx->num_clients]), newfd);

  ++(ctx->num_clients);
  return 0;
}

void client_del(sock_ctx *ctx, int idx) {
  int num_listeners = ctx->last_listener - ctx->first_listener;
  if (idx != ctx->num_clients - 1) {
    // overwrite specified index with last in use index
    memcpy(&(ctx->pfds[idx]), &(ctx->pfds[num_listeners + ctx->num_clients - 1]), sizeof(*ctx->pfds));
    memcpy(&(ctx->tlvs[idx-num_listeners]), &(ctx->tlvs[ctx->num_clients-1]), sizeof(*ctx->tlvs));
  }
  // wipe the no longer in use tlv context
  tlv_init(&(ctx->tlvs[ctx->num_clients-1]), -1);

  --(ctx->num_clients);
}

int tlv_idx(sock_ctx *ctx, int idx) {
  return idx - (ctx->last_listener - ctx->first_listener);
}

int handler(sock_ctx *ctx, int idx, type_t type, uint8_t length, const void *value) {
  tlv_ctx *tlv = &(ctx->tlvs[tlv_idx(ctx, idx)]);
  struct pollfd *pfd = &(ctx->pfds[idx]);

  switch (type) {
    case CMD_CLOSE:
      close(tlv->fd);
      client_del(ctx, idx);
      break;
    case CMD_PING:
      tlv_write(tlv, pfd, REPLY_PING, length, value);
      break;
    case CMD_ADD_SECRET:
      break;
    case CMD_CLEAR_SECRET:
      break;
    case CMD_GENERATE_TOTP:
      break;
    case CMD_VERIFY_TOTP:
      break;
    default:
      tlv_write(tlv, pfd, REPLY_ERROR, 17, "Invalid command.\n");
  }

  return 0;
}

unsigned char * add_secret(unsigned char *b32, size_t len, int digits, int timestep) {
  unsigned char id[32];
  if (getrandom(id, sizeof(id), 0) != sizeof(id)) return NULL;
  ssize_t slen = 0;
  uint8_t *secret = b32_decode(&slen, b32, len);
  otp_t *otp = new_totp(HASH_SHA1, secret, slen, digits, timestep);


}

int loop(sock_ctx *ctx) {
  unsigned char value[255];
  memset_s(value, sizeof(value), 0, sizeof(value));
  lock_mem(value, sizeof(value));

  otp_ht *ht = NULL;
  // HASH_ADD(hh, ht, id, 32, ptr);

  int npfd;
  while ((npfd = (ctx->last_listener - ctx->first_listener) + ctx->num_clients)) {
    int count = poll(ctx->pfds, npfd, 1000);
    if (count > 0) {
      for (int i = 0; i < npfd; ++i) {
        struct pollfd *pfd = &(ctx->pfds[i]);
        int fd = pfd->fd;

        // check whether the fd is a listener or a client
        if (fd >= ctx->first_listener && fd <= ctx->last_listener) {
          // accept new client
          debugf(0, "listener ready %d\n", fd);
          int client_fd;
          if ((client_fd = accept(ctx->pfds[i].fd, NULL, NULL)) >= 0) {
            if (client_add(ctx, client_fd) != 0) return -1;
            fcntl(client_fd, F_SETFL, O_NONBLOCK);
          } else {
            perror("accept: ");
          }
        } else {
          // process existing client
          debugf(0, "client ready %d %d %d\n", fd, pfd->events, pfd->revents);
          tlv_ctx *tlv = &(ctx->tlvs[tlv_idx(ctx, i)]);

          //*
          debugf(0, "fd %3d", tlv->fd);
          debugf(0, ", pos %3d", tlv->pos);
          debugf(0, ", fill %3d", tlv->fill);
          debugf(0, ", state %d", tlv->state);
          if (tlv->fill > 0) debugf(0, ", type %3u", tlv->buf[0]);
          if (tlv->fill > 1) debugf(0, ", length %3u", tlv->buf[1]);
          debugf(0, "\n");
          //*/

          assert(tlv->fd == ctx->pfds[i].fd);
          int rv, length = -1, type = -1;

          // ready to write?
          if (pfd->revents & POLLOUT) {
            if ((rv = tlv_write_continue(tlv)) == 0) {
              // done writing, unset POLLOUT flag
              pfd->events &= ~POLLOUT;
            } else if (errno != EAGAIN) {
              perror("tlv_write_continue: ");
              client_del(ctx, i);
            }
          }

          // ready to read
          if (pfd->revents & POLLIN) {
            if (tlv->state == TLV_IDLE || tlv->state == TLV_READING) {
              // clear errno
              errno = 0;
              if ((rv = tlv_read(tlv, &type, &length, value)) == 1) {
                //*
                debugf(0, "got data: type=%d, length=%d\n", type, length);
                debugf(0, "value=");
                for (int j = 0; j < length; ++j) debugf(0, "%02x", value[j]);
                debugf(0, "\n");
                //*/
                handler(ctx, i, type, length, value);
              } else if (errno != EAGAIN) {
                debugf(0, "return %d\n", rv);
                perror("tlv_read: ");
                client_del(ctx, i);
              } else {
                debugf(0, "rv=%d\n", rv);
              }
            }
          }

          // error/closed
          if (pfd->revents & ~(POLLIN | POLLOUT)) {
            fprintf(stderr, "closed? %d\n", pfd->revents);
            client_del(ctx, i);
          }

        } // end listener/client check
      } // end pfd loop
    } // end if count
  } // end main loop

  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int main(int argc, char *argv[]) {
#pragma GCC diagnostic pop

  // prevent ptrace attachment
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

  // socket context setup
  sock_ctx ctx;
  int nlfd = sd_listen_fds(0);
  if (nlfd == 0) {
    // no systemd socket, so we're going to rebind stdin/stdout
    int fd;
    if ((fd = dup(1)) < 0) {
      fprintf(stderr, "dup(1) failed\n");
      return -1;
    }
    if (dup2(0, fd) != fd) {
      fprintf(stderr, "dup2(0, %d) failed\n", fd);
      return -1;
    }
    if (socket_init(&ctx, 0, 0) != 0) return -1;
    if (client_add(&ctx, fd) != 0) return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);
  } else {
    if (socket_init(&ctx, nlfd, SD_LISTEN_FDS_START) != 0) return -1;
  }

  debugf(0, "socket init okay\n");

  return loop(&ctx);
}
