#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <time.h>

#include "base32.h"
#include "common.h"
#include "hmac.h"
#include "sha1.h"
#include "xendian.h"

static void process(const char *, size_t);
static void process_stdin(void);
static inline uint32_t pow32(uint32_t, uint32_t)
	__attribute__((always_inline, const));
static inline bool xisdigit(char)
	__attribute__((always_inline, const));
static inline bool bigendian(void)
	__attribute__((always_inline, const));

static int digits = 6, period = 30;

static noreturn void
usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-d digits] [-p period] [secret]\n"
		"       %s -h\n",
		argv0, argv0);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	int opt;
	static const struct option longopts[] = {
		{"digits", required_argument, 0, 'd'},
		{"help",   no_argument,       0, 'h'},
		{"period", required_argument, 0, 'p'},
		{0},
	};

	argv[0] = basename(argv[0]);
	while ((opt = getopt_long(argc, argv, "d:hp:", longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			/* TODO: Open the manual page! */
			usage(argv[0]);
			break;
		case 'd':
		case 'p': {
			/* strtol() allows for numbers with leading spaces and a
			   ‘+’/‘-’.  We don’t want that, so assert that the input
			   begins with a number. */
			if (!xisdigit(optarg[0]))
				errx(1, "%s: Invalid integer", optarg);

			char *endptr;
			long n = strtol(optarg, &endptr, 10);

			/* There are trailing invalid digits */
			if (*endptr != 0)
				errx(1, "%s: Invalid integer", optarg);

			/* The number was too large.  We asserted that the input
			   didn’t start with ‘-’ so we can ignore checking for
			   LONG_MIN. */
			if (n > INT_MAX)
				errno = ERANGE;
				err(1, "%s", optarg);
			}

			if (n == 0)
				errx(1, "%s: Integer must be non-zero", optarg);
			if (opt == 'd')
				digits = (int)n;
			else
				period = (int)n;
			break;
		}
		default:
			usage(argv[0]);
		}
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 0:
		process_stdin();
		break;
	case 1:
		process(argv[0], strlen(argv[0]));
		break;
	default:
		usage(argv[-optind]);
	}

	return EXIT_SUCCESS;
}

void
process_stdin(void)
{
	ssize_t nr;
	size_t len;
	char *line = NULL;
	while ((nr = getline(&line, &len, stdin)) != -1) {
		if (line[nr - 1] == '\n')
			line[--nr] = 0;
		process(line, nr);
	}
	if (errno != 0)
		err(1, "getline");
}

void
process(const char *s, size_t n)
{
	/* Remove padding bytes */
	while (n > 0 && s[n - 1] == '=')
		n--;
	if (n == 0)
		errx(1, "Empty Base32 input");

	static uint8_t _key[256];
	uint8_t *key = _key;

	size_t keysz = n * 5 / 8;
	if (keysz > sizeof(_key)) {
		if ((key = malloc(keysz)) == NULL)
			err(1, "malloc");
	}

	if (!b32toa(key, s, n))
		errx(1, "%s: Invalid Base32 input", s);

	/* time(2) claims that this call will never fail if passed a NULL
	   argument.  We cast the time_t to uint64_t which will always be
	   safe to do. */
	uint64_t epoch = htobe64((uint64_t)time(NULL) / (uint64_t)period);
	uint8_t dgst[SHA1DGSTSZ];
	hmac_sha1(dgst, key, keysz, (uint8_t *)&epoch, sizeof(epoch));

	int off = dgst[19] & 0x0F;
	uint32_t binc = (dgst[off + 0] & 0x7F) << 24
                  | (dgst[off + 1] & 0xFF) << 16
                  | (dgst[off + 2] & 0xFF) <<  8
                  | (dgst[off + 3] & 0xFF) <<  0;
	printf("%0*" PRId32 "\n", digits, binc % pow32(10, digits));

	if (key != _key)
		free(key);
}

/* TODO: Check for overflow? */
uint32_t
pow32(uint32_t x, uint32_t y)
{
	uint32_t n = x;
	if (y == 0)
		return 1;
	while (--y != 0)
		x *= n;
	return x;
}

bool
xisdigit(char ch)
{
	return ch >= '0' && ch <= '9';
}

bool
bigendian(void)
{
	union {
		uint16_t u16;
		uint8_t  u8[2];
	} u = {
		.u16 = 0x0102,
	};
	u.u16 = 0x0102U;
	return u.u8[0] == 1;
}
