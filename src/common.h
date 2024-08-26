#ifndef TOTP_COMMON_H
#define TOTP_COMMON_H

#if !__GNUC__
#	define __attribute__(x)
#endif

/* TODO: Is this endian stuff potentially useful? */

/* If C23 or newer include this to get byte-order macros */
#if __STDC_VERSION__ >= 202311L
#	include <stdbit.h>
#endif

#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)        \
	|| (defined(__STDC_ENDIAN_NATIVE__)                                        \
        && __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__)
#	define ENDIAN_BIG 1
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)   \
	|| (defined(__STDC_ENDIAN_NATIVE__)                                        \
        && __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__)
#	define ENDIAN_LITTLE 1
#else
#	define ENDIAN_UNKNOWN 1
#endif

#endif /* !TOTP_COMMON_H */
