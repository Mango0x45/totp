#ifndef TOTP_HMAC_H
#define TOTP_HMAC_H

#include <stddef.h>
#include <stdint.h>

void hmac_sha1(uint8_t *restrict,
               const uint8_t *restrict, size_t,
               const uint8_t *restrict, size_t);

#endif /* !TOTP_HMAC_H */
