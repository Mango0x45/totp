#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static const uint8_t ctov[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1,  0, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

bool
b32toa(char *dst, const char *src, size_t len)
{
	char c;
	size_t pad = 0;
	uint8_t vs[8];

	while (src[len - 1 - pad] == '=') {
		if (++pad > 6)
			return false;
	}

	for (size_t i = 0; i < len; i += 8) {
		for (size_t j = 0; j < 8; j++) {
			c = src[i + j];
			vs[j] = ctov[(uint8_t)c];
			if (vs[j] == 255) {
				if (c == '=' && j >= 8 - pad) {
					vs[j] = 0;
				} else {
					return false;
				}
			}
		}

		dst[i * 5 / 8 + 0] = (vs[0] << 3) | (vs[1] >> 2);
		dst[i * 5 / 8 + 1] = (vs[1] << 6) | (vs[2] << 1) | (vs[3] >> 4);
		dst[i * 5 / 8 + 2] = (vs[3] << 4) | (vs[4] >> 1);
		dst[i * 5 / 8 + 3] = (vs[4] << 7) | (vs[5] << 2) | (vs[6] >> 3);
		dst[i * 5 / 8 + 4] = (vs[6] << 5) |  vs[7];
	}

	return true;
}
