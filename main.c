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
	"       %s -u [uri ...]\n";

static void     usage(void);
static void     totp_print(struct totp_config, char *, bool);
static bool     strtol_safe(long *, const char *);
static bool     totp(struct totp_config, uint32_t *);
static uint32_t pow32(uint32_t, uint32_t);
static bool     uri_parse(struct totp_config *, const char *);
static bool     big_endian(void);

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

	if (argc == 0) {
		buf = NULL;
		bufsiz = 0;

		while ((nr = getline(&buf, &bufsiz, stdin)) > 0) {
			if (buf[--nr] == '\n')
				buf[nr] = '\0';
			totp_print(conf, buf, uflag);
		}
		free(buf);
	} else for (int i = 0; i < argc; i++)
		totp_print(conf, argv[i], uflag);

	return rv;
}

void
totp_print(struct totp_config conf, char *buf, bool uflag)
{
	uint32_t code;
	
	if (uflag) {
		conf = TOTP_DEFAULT;
		if (!uri_parse(&conf, buf))
			return;
	} else
		conf.enc_sec = buf;
	if (totp(conf, &code))
		printf("%0*d\n", (int)conf.len, code);
	if (uflag)
		free((void *)conf.enc_sec);
}

bool
uri_parse(struct totp_config *conf, const char *uri_raw)
{
	bool reject;
	size_t len;
	UriUriA uri;
	UriQueryListA *qs;
	const char *epos;

	if (uriParseSingleUriA(&uri, uri_raw, &epos) != URI_SUCCESS) {
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
			if ((conf->enc_sec = strdup(p->value)) == NULL)
				err(EXIT_FAILURE, "strdup");
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
	bool clean;
	uint8_t *key;
	char *enc_sec;
	uchar *mac;
	time_t epoch;
	uint8_t buf[sizeof(time_t)];
	uint32_t binc;
	size_t keylen, enc_sec_len, old;
	
	/* conf.enc_sec needs to be ‘=’ padded to a multiple of 8 */
	old = enc_sec_len = strlen(conf.enc_sec);
	if (enc_sec_len % 8 == 0) {
		enc_sec = (char *)conf.enc_sec;
		clean = false;
	} else {
		enc_sec_len += 8 - enc_sec_len % 8;
		if ((enc_sec = malloc(enc_sec_len)) == NULL)
			err(EXIT_FAILURE, "malloc");
		memcpy(enc_sec, conf.enc_sec, old);
		memset(enc_sec + old, '=', enc_sec_len - old);
		clean = true;
	}

	keylen = old / 1.6;
	if ((key = calloc(keylen + 1, sizeof(char))) == NULL)
		err(EXIT_FAILURE, "calloc");
	b32toa(key, enc_sec, enc_sec_len);

	if (time(&epoch) == (time_t)-1) {
		warn("time");
		return false;
	}

	epoch /= conf.p;

	if (big_endian())
		memcpy(buf, &epoch, sizeof(time_t));
	else {
		for (size_t i = 0; i < sizeof(buf); i++)
			buf[i] = (epoch >> (8 * (sizeof(buf) - 1 - i))) & 0xFF;
	}

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

	if (clean)
		free(enc_sec);
	free(key);
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

bool
big_endian(void)
{
	unsigned n = 0x01020304;
	uchar *ptr = (uchar *)&n;

	return *ptr == 1;
}
