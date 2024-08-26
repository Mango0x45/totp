#ifndef TOTP_SHA1_H
#define TOTP_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1DGSTSZ (20)
#define SHA1BLKSZ  (64)

typedef struct {
	uint32_t dgst[SHA1DGSTSZ / sizeof(uint32_t)];
	uint64_t msgsz;
	uint8_t buf[SHA1BLKSZ];
	size_t bufsz;
} sha1_t;

void sha1init(sha1_t *);
void sha1hash(sha1_t *, const uint8_t *, size_t);
void sha1end(sha1_t *, uint8_t *);

#endif /* !TOTP_SHA1_H */
