#include "common.h"
#include "sha1.h"
#include "xendian.h"

static inline uint32_t rotl32(uint32_t x, uint8_t bits)
	__attribute__((always_inline, const));

static const uint32_t K[] = {
	0x5A827999,
	0x6ED9EBA1,
	0x8F1BBCDC,
	0xCA62C1D6,
};

void
sha1hashblk(sha1_t *s, const uint8_t *blk)
{
	uint32_t w[80];
	uint32_t a, b, c, d, e, tmp;

	for (int i = 0; i < 16; i++)
		w[i] = htobe32(((uint32_t *)blk)[i]);
	for (int i = 16; i < 32; i++)
		w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
	for (int i = 32; i < 80; i++)
		w[i] = rotl32(w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32], 2);

	a = s->dgst[0];
	b = s->dgst[1];
	c = s->dgst[2];
	d = s->dgst[3];
	e = s->dgst[4];

	for (int i = 0; i < 80; i++) {
		uint32_t f, k;

		if (i < 20) {
			f = b&c | ~b&d;
			k = K[0];
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = K[1];
		} else if (i < 60) {
			f = b&c | b&d | c&d;
			k = K[2];
		} else {
			f = b ^ c ^ d;
			k = K[3];
		}

		tmp = rotl32(a, 5) + f + e + w[i] + k;
		e = d;
		d = c;
		c = rotl32(b, 30);
		b = a;
		a = tmp;
	}

	s->dgst[0] += a;
	s->dgst[1] += b;
	s->dgst[2] += c;
	s->dgst[3] += d;
	s->dgst[4] += e;
}

uint32_t
rotl32(uint32_t x, uint8_t bits)
{
#if (__GNUC__ || __TINYC__) && __x86_64__
	__asm__ ("roll %1, %0" : "+r" (x) : "c" (bits) : "cc");
	return x;
#elif __GNUC__ && __aarch64__ /* TODO: Test this! */
	__asm__ ("ror %0, %0, %1" : "+r" (x) : "c" (-bits));
	return x;
#else
	return (x << bits) | (x >> (32 - bits));
#endif
}
