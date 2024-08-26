#include <err.h>
#include <errno.h>
#include <string.h>

#include "sha1.h"
#include "xendian.h"

#define lengthof(x) (sizeof(x) / sizeof(*(x)))
#define MIN(x, y)   ((x) < (y) ? (x) : (y))

void sha1hashblk(sha1_t *, const uint8_t *);

void
sha1init(sha1_t *s)
{
	static const uint32_t H[] = {
		0x67452301,
		0xEFCDAB89,
		0x98BADCFE,
		0x10325476,
		0xC3D2E1F0,
	};
	memcpy(s->dgst, H, sizeof(H));
	s->msgsz = s->bufsz = 0;
}

void
sha1hash(sha1_t *s, const uint8_t *msg, size_t msgsz)
{
	if (s->msgsz + (msgsz * 8) < s->msgsz) {
		errno = EOVERFLOW;
		err(1, "sha1");
	}

	s->msgsz += msgsz * 8;

	while (msgsz != 0) {
		size_t free_space = SHA1BLKSZ - s->bufsz;
		size_t ncpy = MIN(msgsz, free_space);
		memcpy(s->buf + s->bufsz, msg, ncpy);
		s->bufsz += ncpy;
		msg += ncpy;
		msgsz -= ncpy;

		if (s->bufsz == SHA1BLKSZ) {
			sha1hashblk(s, s->buf);
			s->bufsz = 0;
		}
	}
}

void
sha1end(sha1_t *s, uint8_t *dgst)
{
	s->buf[s->bufsz++] = 0x80;

	if (s->bufsz > SHA1BLKSZ - sizeof(uint64_t)) {
		while (s->bufsz < SHA1BLKSZ)
			s->buf[s->bufsz++] = 0;
		sha1hashblk(s, s->buf);
		s->bufsz = 0;
	}

	while (s->bufsz < 56)
		s->buf[s->bufsz++] = 0;
	uint64_t n = htobe64(s->msgsz);
	memcpy(s->buf + (SHA1BLKSZ/8 - 1)*sizeof(uint64_t), &n, sizeof(n));

	sha1hashblk(s, s->buf);

	for (size_t i = 0; i < lengthof(s->dgst); i++) {
		/* Pretty please compiler optimize this */
		uint32_t n = htobe32(s->dgst[i]);
		memcpy(dgst + i*sizeof(uint32_t), &n, sizeof(n));
	}
}
