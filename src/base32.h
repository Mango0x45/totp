#ifndef TOTP_BASE32_H
#define TOTP_BASE32_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool b32toa(uint8_t *restrict, const char *restrict, size_t);

#endif /* !TOTP_BASE32_H */
