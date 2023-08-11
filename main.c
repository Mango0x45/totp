/* References: https://datatracker.ietf.org/doc/html/rfc4226#section-5 */

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/hmac.h>
#include <uriparser/Uri.h>
#include <uriparser/UriBase.h>

#include "b32.h"

#define STREQ(x, y) (strcmp(x, y) == 0)
#define PRINT_CODE(w, x) printf("%0*d\n", (int)w, x)
#define WARNX_AND_RET(...) \
	do { \
		rv = EXIT_FAILURE; \
		warnx(__VA_ARGS__); \
		return false; \
	} while (false)

#define TOTP_DEFAULT (struct totp_config){ .len = 6, .p = 30 }

typedef unsigned char uchar;

struct totp_config {
	const char *enc_sec;
	long len, p;
};

extern char *__progname;

static int rv;

static const char *bad_scheme = "Invalid scheme ‘%.*s’; expected ‘otpauth’";
static const char *bad_param = "Invalid ‘%s’ parameter provided";
static const char *empty_param = "Empty ‘%s’ parameter provided";
static const char *usage_s =
	"Usage: %s [-d digits] [-p period] [secret ...]\n"
	"       %s [-u] [uri ...]\n";

static void      usage(void);
static bool      strtol_safe(long *, const char *);
static bool      totp(struct totp_config, uint32_t *);
static uint32_t  pow32(uint32_t, uint32_t);
static bool      uri_parse(struct totp_config *, const char *);

void
usage(void)
{
	fprintf(stderr, usage_s, __progname, __progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int opt;
	bool uflag = false;
	long n;
	char *buf;
	size_t bufsiz;
	ssize_t nr;
	uint32_t code;
	struct totp_config conf = TOTP_DEFAULT;
	struct option longopts[] = {
		{"digits", required_argument, 0, 'd'},
		{"period", required_argument, 0, 'p'},
		{"uri",    no_argument,       0, 'u'},
		{ NULL,    0,                 0,  0 },
	};

	while ((opt = getopt_long(argc, argv, "d:p:u", longopts, NULL)) != -1) {
		switch (opt) {
		case 'd':
		case 'p':
			if (!strtol_safe(&n, optarg))
				errx(EXIT_FAILURE, bad_param,
				     opt == 'd' ? "digits" : "period");
			if (opt == 'd')
				conf.len = n;
			else
				conf.p = n;
			break;
		case 'u':
			uflag = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	for (int i = 0; i < argc; i++) {
		conf.enc_sec = argv[i];
		if (uflag) {
			conf = TOTP_DEFAULT;
			if (!uri_parse(&conf, argv[i])) {
				rv = EXIT_FAILURE;
				continue;
			}
		} else
			conf.enc_sec = argv[i];
		if (totp(conf, &code))
			PRINT_CODE(conf.len, code);
	}

	if (argc == 0) {
		buf = NULL;
		bufsiz = 0;

		while ((nr = getline(&buf, &bufsiz, stdin)) > 0) {
			if (buf[--nr] == '\n')
				buf[nr] = '\0';
			if (uflag) {
				conf = TOTP_DEFAULT;
				if (!uri_parse(&conf, buf)) {
					rv = EXIT_FAILURE;
					continue;
				}
			} else
				conf.enc_sec = buf;
			if (totp(conf, &code))
				PRINT_CODE(conf.len, code);
		}
	}

	return rv;
}

bool
uri_parse(struct totp_config *conf, const char *uri_raw)
{
	int n;
	bool reject;
	size_t len;
	UriUriA uri;
	UriQueryListA *qs;
	const char *epos;

	if ((n = uriParseSingleUriA(&uri, uri_raw, &epos)) != URI_SUCCESS) {
		len = epos - uri_raw + 24 + strlen(__progname);
		WARNX_AND_RET("Failed to parse URI ‘%s’\n"
		              "%*c Error detected here",
		              uri_raw, (int)len, '^');
	}

	len = uri.scheme.afterLast - uri.scheme.first;
	reject = len != strlen("otpauth");
	reject = reject || strncasecmp(uri.scheme.first, "otpauth", len) != 0;

	if (reject)
		WARNX_AND_RET(bad_scheme, (int)len, uri.scheme.first);
	if (uriDissectQueryMallocA(&qs, NULL, uri.query.first,
	                           uri.query.afterLast) != URI_SUCCESS)
		WARNX_AND_RET("Failed to parse query string");

	for (UriQueryListA *p = qs; p != NULL; p = p->next) {
		if (STREQ(p->key, "secret")) {
			if (p->value == NULL)
				WARNX_AND_RET("Secret key has no value");
			conf->enc_sec = p->value;
		} else if (STREQ(p->key, "digits")) {
			if (p->value == NULL)
				WARNX_AND_RET(empty_param, "digits");
			if (!strtol_safe(&conf->len, p->value))
				WARNX_AND_RET(bad_param, "digits");
		} else if (STREQ(p->key, "period")) {
			if (p->value == NULL)
				WARNX_AND_RET(empty_param, "period");
			if (!strtol_safe(&conf->p, p->value))
				WARNX_AND_RET(bad_param, "period");
		}
	}

	uriFreeQueryListA(qs);
	uriFreeUriMembersA(&uri);

	return true;
}

bool
totp(struct totp_config conf, uint32_t *code)
{
	int off;
	char *key;
	uchar *mac;
	time_t epoch;
	size_t keylen;
	uint8_t buf[sizeof(time_t)];  /* Enough for a 64bit num */
	uint32_t binc;
	
	/* TODO: conf.enc_sec needs to be ‘=’ padded to a multiple of 8 */

	/* When decoding base32, you need ceil(conf.enc_sec / 1.6) bytes */
	keylen = strlen(conf.enc_sec) / 1.6 + 1;
	key = calloc(keylen, sizeof(char));
	b32toa(key, conf.enc_sec, strlen(conf.enc_sec));

	if (time(&epoch) == (time_t)-1) {
		warn("time");
		return false;
	}

	epoch /= conf.p;

	buf[0] = (epoch >> 56) & 0xFF;
	buf[1] = (epoch >> 48) & 0xFF;
	buf[2] = (epoch >> 40) & 0xFF;
	buf[3] = (epoch >> 32) & 0xFF;
	buf[4] = (epoch >> 24) & 0xFF;
	buf[5] = (epoch >> 16) & 0xFF;
	buf[6] = (epoch >>  8) & 0xFF;
	buf[7] = (epoch >>  0) & 0xFF;
	
	mac = HMAC(EVP_sha1(), key, keylen, buf, sizeof(buf), NULL, NULL);
	if (mac == NULL)
		WARNX_AND_RET("Failed to compute HMAC SHA-1 hash");

        /* SHA1 hashes are 20 bytes long */
	off = mac[19] & 0x0F;
	binc = (mac[off + 0] & 0x7F) << 24
             | (mac[off + 1] & 0xFF) << 16
             | (mac[off + 2] & 0xFF) <<  8
             | (mac[off + 3] & 0xFF) <<  0;

	*code = binc % pow32(10, conf.len);
	return true;
}

bool
strtol_safe(long *n, const char *s)
{
	char *e;
	*n = strtol(s, &e, 10);
	return *n > 0 && *s != '\0' && *e == '\0';
}

/* This could overflow if you did some autistic shit */
uint32_t
pow32(uint32_t x, uint32_t y)
{
	int n = x;
	if (y == 0)
		return 1;
	while (--y != 0)
		x *= n;
	return x;
}
