#pragma once
#include <sys/types.h>
uint8_t * b32_decode(ssize_t *olen, const char *str, size_t len);
