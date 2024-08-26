#include <string.h>

#include "sha1.h"

#define IPAD (0x36)
#define OPAD (0x5C)

void
hmac_sha1(uint8_t *restrict out,
          const uint8_t *restrict key, size_t keysz,
          const uint8_t *restrict msg, size_t msgsz)
{
	uint8_t keyext[SHA1BLKSZ] = {0},
	        keyipad[SHA1BLKSZ],
			keyopad[SHA1BLKSZ];

	if (keysz > SHA1BLKSZ) {
		sha1_t sha;
		sha1init(&sha);
		sha1hash(&sha, key, keysz);
		sha1end(&sha, keyext);
	} else
		memcpy(keyext, key, keysz);

	for (size_t i = 0; i < sizeof(keyext); i++) {
		keyipad[i] = keyext[i] ^ IPAD;
		keyopad[i] = keyext[i] ^ OPAD;
	}

	sha1_t sha;
	uint8_t dgst[SHA1DGSTSZ];
	sha1init(&sha);
	sha1hash(&sha, keyipad, sizeof(keyipad));
	sha1hash(&sha, msg, msgsz);
	sha1end(&sha, dgst);

	sha1init(&sha);
	sha1hash(&sha, keyopad, sizeof(keyopad));
	sha1hash(&sha, dgst, sizeof(dgst));
	sha1end(&sha, out);
}
