#include <arm_acle.h>
#include <arm_neon.h>

#include "sha1.h"

#define R(mi, mj, mk, ml, ei, ej, ti, c, magic)                                \
	do {                                                                       \
		ei = vsha1h_u32(vgetq_lane_u32(abcd, 0));                              \
		abcd = vsha1##c##q_u32(abcd, ej, ti);                                  \
		ti = vaddq_u32(mi, vdupq_n_u32(magic));                                \
		mj = vsha1su1q_u32(mj, mi);                                            \
		mk = vsha1su0q_u32(mk, ml, mi);                                        \
	} while (0)

void
sha1hashblk(sha1_t *s, const uint8_t *blk)
{
	uint32_t e0, e_save, e1;
	uint32x4_t abcd, abcd_save;
	uint32x4_t tmp0, tmp1;
	uint32x4_t msg0, msg1, msg2, msg3;

	abcd_save = abcd = vld1q_u32(s->dgst);
	e_save = e0 = s->dgst[4];

	/* Load message */
	msg0 = vld1q_u32((uint32_t *)(blk + 0x00));
	msg1 = vld1q_u32((uint32_t *)(blk + 0x10));
	msg2 = vld1q_u32((uint32_t *)(blk + 0x20));
	msg3 = vld1q_u32((uint32_t *)(blk + 0x30));

	/* Reverse for little endian */
	msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
	msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
	msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
	msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

	tmp0 = vaddq_u32(msg0, vdupq_n_u32(0x5A827999));
	tmp1 = vaddq_u32(msg1, vdupq_n_u32(0x5A827999));

	/* Rounds 0–3 */
	e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1cq_u32(abcd, e0, tmp0);
	tmp0 = vaddq_u32(msg2, vdupq_n_u32(0x5A827999));
	msg0 = vsha1su0q_u32(msg0, msg1, msg2);

	R(msg3, msg0, msg1, msg2, e0, e1, tmp1, c, 0x5A827999); /* Rounds 04–07 */
	R(msg0, msg1, msg2, msg3, e1, e0, tmp0, c, 0x5A827999); /* Rounds 08–11 */
	R(msg1, msg2, msg3, msg0, e0, e1, tmp1, c, 0x6ED9EBA1); /* Rounds 12–15 */
	R(msg2, msg3, msg0, msg1, e1, e0, tmp0, c, 0x6ED9EBA1); /* Rounds 16–19 */
	R(msg3, msg0, msg1, msg2, e0, e1, tmp1, p, 0x6ED9EBA1); /* Rounds 20–23 */
	R(msg0, msg1, msg2, msg3, e1, e0, tmp0, p, 0x6ED9EBA1); /* Rounds 24–27 */
	R(msg1, msg2, msg3, msg0, e0, e1, tmp1, p, 0x6ED9EBA1); /* Rounds 28–31 */
	R(msg2, msg3, msg0, msg1, e1, e0, tmp0, p, 0x8F1BBCDC); /* Rounds 32–35 */
	R(msg3, msg0, msg1, msg2, e0, e1, tmp1, p, 0x8F1BBCDC); /* Rounds 36–39 */
	R(msg0, msg1, msg2, msg3, e1, e0, tmp0, m, 0x8F1BBCDC); /* Rounds 40–43 */
	R(msg1, msg2, msg3, msg0, e0, e1, tmp1, m, 0x8F1BBCDC); /* Rounds 44–47 */
	R(msg2, msg3, msg0, msg1, e1, e0, tmp0, m, 0x8F1BBCDC); /* Rounds 48–51 */
	R(msg3, msg0, msg1, msg2, e0, e1, tmp1, m, 0xCA62C1D6); /* Rounds 52–55 */
	R(msg0, msg1, msg2, msg3, e1, e0, tmp0, m, 0xCA62C1D6); /* Rounds 56–59 */
	R(msg1, msg2, msg3, msg0, e0, e1, tmp1, p, 0xCA62C1D6); /* Rounds 60–63 */
	R(msg2, msg3, msg0, msg1, e1, e0, tmp0, p, 0xCA62C1D6); /* Rounds 64–67 */

	/* Rounds 68–71 */
	e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e1, tmp1);
	tmp1 = vaddq_u32(msg3, vdupq_n_u32(0xCA62C1D6));
	msg0 = vsha1su1q_u32(msg0, msg3);

	/* Rounds 72–75 */
	e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e0, tmp0);

	/* Rounds 76–79 */
	e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e1, tmp1);

	e0 += e_save;
	abcd = vaddq_u32(abcd_save, abcd);

	vst1q_u32(s->dgst, abcd);
	s->dgst[4] = e0;
}
