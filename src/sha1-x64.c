#include <immintrin.h>

#include "sha1.h"

#define R(mi, mj, mk, ml, ei, ej, f)                                           \
	do {                                                                       \
		ei = _mm_sha1nexte_epu32(ei, mi);                                      \
		ej = abcd;                                                             \
		mj = _mm_sha1msg2_epu32(mj, mi);                                       \
		abcd = _mm_sha1rnds4_epu32(abcd, ei, f);                               \
		ml = _mm_sha1msg1_epu32(ml, mi);                                       \
		mk = _mm_xor_si128(mk, mi);                                            \
	} while (0)

void
sha1hashblk(sha1_t *s, const uint8_t *blk)
{
	__m128i abcd, e0, e1;
	__m128i abcd_save, e_save;
	__m128i msg0, msg1, msg2, msg3;

	/* Masks for swapping endianness.  We make BSWAPDMSK a macro to
	   please the compiler (it wants immediate values). */
#define bswapdmsk 0x1B  /* 0b00'01'10'11 */
	const __m128i bswapbmsk = _mm_set_epi64x(
		0x0001020304050607ULL,
		0x08090a0b0c0d0e0fULL
	);

	const __m128i *blkx = (const __m128i *)blk;

	abcd_save = abcd =
		_mm_shuffle_epi32(_mm_loadu_si128((__m128i *)s->dgst), bswapdmsk);
	e_save = e0 = _mm_set_epi32(s->dgst[4], 0, 0, 0);

	/* Rounds 0–3 */
	msg0 = _mm_shuffle_epi8(_mm_loadu_si128(blkx + 0), bswapbmsk);
	e0 = _mm_add_epi32(e0, msg0);
	e1 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);

	/* Rounds 4–7 */
	msg1 = _mm_shuffle_epi8(_mm_loadu_si128(blkx + 1), bswapbmsk);
	e1 = _mm_sha1nexte_epu32(e1, msg1);
	e0 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
	msg0 = _mm_sha1msg1_epu32(msg0, msg1);

	/* Rounds 8–11 */
	msg2 = _mm_shuffle_epi8(_mm_loadu_si128(blkx + 2), bswapbmsk);
	e0 = _mm_sha1nexte_epu32(e0, msg2);
	e1 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
	msg1 = _mm_sha1msg1_epu32(msg1, msg2);
	msg0 = _mm_xor_si128(msg0, msg2);

	msg3 = _mm_shuffle_epi8(_mm_loadu_si128(blkx + 3), bswapbmsk);
	R(msg3, msg0, msg1, msg2, e1, e0, 0); /* Rounds 12–15 */
	R(msg0, msg1, msg2, msg3, e0, e1, 0); /* Rounds 16–19 */
	R(msg1, msg2, msg3, msg0, e1, e0, 1); /* Rounds 20–23 */
	R(msg2, msg3, msg0, msg1, e0, e1, 1); /* Rounds 24–27 */
	R(msg3, msg0, msg1, msg2, e1, e0, 1); /* Rounds 28–31 */
	R(msg0, msg1, msg2, msg3, e0, e1, 1); /* Rounds 32–35 */
	R(msg1, msg2, msg3, msg0, e1, e0, 1); /* Rounds 36–39 */
	R(msg2, msg3, msg0, msg1, e0, e1, 2); /* Rounds 40–43 */
	R(msg3, msg0, msg1, msg2, e1, e0, 2); /* Rounds 44–47 */
	R(msg0, msg1, msg2, msg3, e0, e1, 2); /* Rounds 48–51 */
	R(msg1, msg2, msg3, msg0, e1, e0, 2); /* Rounds 52–55 */
	R(msg2, msg3, msg0, msg1, e0, e1, 2); /* Rounds 56–59 */
	R(msg3, msg0, msg1, msg2, e1, e0, 3); /* Rounds 60–63 */
	R(msg0, msg1, msg2, msg3, e0, e1, 3); /* Rounds 64–67 */

	/* Rounds 68–71 */
	e1 = _mm_sha1nexte_epu32(e1, msg1);
	e0 = abcd;
	msg2 = _mm_sha1msg2_epu32(msg2, msg1);
	abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
	msg3 = _mm_xor_si128(msg3, msg1);

	/* Rounds 72–75 */
	e0 = _mm_sha1nexte_epu32(e0, msg2);
	e1 = abcd;
	msg3 = _mm_sha1msg2_epu32(msg3, msg2);
	abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);

	/* Rounds 76–79 */
	e1 = _mm_sha1nexte_epu32(e1, msg3);
	e0 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);

	e0 = _mm_sha1nexte_epu32(e0, e_save);
	abcd = _mm_add_epi32(abcd, abcd_save);

	_mm_storeu_si128((__m128i *)s->dgst, _mm_shuffle_epi32(abcd, bswapdmsk));
	s->dgst[4] = _mm_extract_epi32(e0, 3);
}
