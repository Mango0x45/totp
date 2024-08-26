#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBS_NO_THREADS
#include "cbs.h"

#define PREFIX "/usr/local"

#define streq(x, y) (strcmp(x, y) == 0)
#define CMDPRC(c)                                                              \
	do {                                                                       \
		int ec;                                                                \
		cmdput(c);                                                             \
		if ((ec = cmdexec(c)) != EXIT_SUCCESS)                                 \
			errx(1, "%s terminated with exit-code %d", *c.buf, ec);            \
		strszero(&c);                                                          \
	} while (false)

static void cc(void *);
static void ld(void);
static char *mkoutpath(const char *);
static char *xstrdup(const char *);
static void *xmalloc(size_t);

static char *warnings[] = {
	"-Wall",
	"-Wextra",
	"-Wpedantic",
	"-Wno-parentheses",
};

static char *cflags_all[] = {
	"-std=c11",
#if __GLIBC__
	"-D_GNU_SOURCE",
#endif
};

static char *cflags_dbg[] = {
	"-g3",
	"-ggdb3",
	"-O0",
};

static char *cflags_rls[] = {
	"-DNDEBUG=1",
	"-flto",
	"-march=native",
	"-mtune=native",
	"-O3",
};

static const char *argv0;
static bool fflag, Sflag, rflag;
static char *oflag = "totp", *pflag = "generic";

static void
usage(void)
{
	fprintf(stderr,
	        "Usage: %s [-p generic|arm64|x64] [-o outfile] [-fSr]\n"
	        "       %s clean | install\n",
	        argv0, argv0);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	cbsinit(argc, argv);
	rebuild();

	argv0 = basename(argv[0]);

	int opt;
	static const struct option longopts[] = {
		{"force",        no_argument,       0, 'f'},
		{"no-sanitizer", no_argument,       0, 'S'},
		{"output",       required_argument, 0, 'o'},
		{"profile",      required_argument, 0, 'p'},
		{"release",      no_argument,       0, 'r'},
		{0},
	};

	while ((opt = getopt_long(argc, argv, "fSo:p:r", longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			fflag = true;
			break;
		case 'r':
			rflag = true;
			/* fallthrough */
		case 'S':
			Sflag = true;
			break;
		case 'o':
			oflag = xstrdup(optarg);
			break;
		case 'p':
			if (!streq(optarg, "generic")
			 && !streq(optarg, "arm64")
			 && !streq(optarg, "x64"))
			{
				fprintf(stderr, "%s: invalid profile -- '%s'\n", argv0, optarg);
				usage();
			}
			pflag = xstrdup(optarg);
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage();
	if (argc == 1) {
		struct strs cmd = {0};

		if (streq(argv[0], "clean")) {
			strspushl(&cmd, "find", ".",
				"(",
					"-name", "totp",
					"-or", "-name", "totp-*",
					"-or", "-name", "*.o",
				")", "-delete"
			);
			CMDPRC(cmd);
		} else if (streq(argv[0], "install")) {
			char *bin, *man;
			bin = mkoutpath("/bin");
			man = mkoutpath("/share/man/man1");

			strspushl(&cmd, "mkdir", "-p", bin, man);
			CMDPRC(cmd);

			char *stripprg = binexists(     "strip") ?      "strip"
			               : binexists("llvm-strip") ? "llvm-strip"
			               : NULL;
			if (stripprg != NULL) {
				strspushl(&cmd, stripprg, "--strip-all", "totp");
				CMDPRC(cmd);
			}

			strspushl(&cmd, "cp", "totp", bin);
			CMDPRC(cmd);
			strspushl(&cmd, "cp", "totp.1", man);
			CMDPRC(cmd);
		} else {
			fprintf(stderr, "%s: invalid subcommand -- '%s'\n", argv0, *argv);
			usage();
		}

		return EXIT_SUCCESS;
	}

	glob_t g;
	if (glob("src/*.c", 0, NULL, &g) != 0)
		errx(1, "glob: failed to glob");

	char *ext = xmalloc(strlen(pflag) + sizeof("-.c"));
	sprintf(ext, "-%s.c", pflag);

	for (size_t i = 0; i < g.gl_pathc; i++) {
		if (strchr(g.gl_pathv[i], '-') != NULL
		 && strstr(g.gl_pathv[i], ext) == NULL)
		{
			continue;
		}
		cc(g.gl_pathv[i]);
	}

	globfree(&g);
	ld();
}

void
cc(void *arg)
{
	struct strs cmd = {0};
	char *dst = swpext(arg, "o"), *src = arg;

	if (!fflag && fmdnewer(dst, src))
		goto out;

	strspushenvl(&cmd, "CC", "cc");
	strspush(&cmd, cflags_all, lengthof(cflags_all));
	if (rflag)
		strspushenv(&cmd, "CFLAGS", cflags_rls, lengthof(cflags_rls));
	else
		strspushenv(&cmd, "CFLAGS", cflags_dbg, lengthof(cflags_dbg));

	if (strstr(arg, "-x64.c") != NULL)
		strspushl(&cmd, "-msha", "-mssse3");
	if (strstr(arg, "-arm64.c") != NULL)
		strspushl(&cmd, "-march=native+crypto");

	if (!Sflag)
		strspushl(&cmd, "-fsanitize=address,undefined");
	strspushl(&cmd, "-o", dst, "-c", src);

	CMDPRC(cmd);
	strsfree(&cmd);
out:
	free(dst);
}

void
ld(void)
{
	glob_t g;
	bool dobuild = fflag;
	struct strs cmd = {0};

	strspushenvl(&cmd, "CC", "cc");
	strspush(&cmd, cflags_all, lengthof(cflags_all));
	if (rflag)
		strspushenv(&cmd, "CFLAGS", cflags_rls, lengthof(cflags_rls));
	else
		strspushenv(&cmd, "CFLAGS", cflags_dbg, lengthof(cflags_dbg));
	if (!Sflag)
		strspushl(&cmd, "-fsanitize=address,undefined");
	strspushl(&cmd, "-o", oflag);

	assert(glob("src/*.o", 0, NULL, &g) == 0);

	char *ext = xmalloc(strlen(pflag) + sizeof("-.o"));
	sprintf(ext, "-%s.o", pflag);

	for (size_t i = 0; i < g.gl_pathc; i++) {
		if (strchr(g.gl_pathv[i], '-') != NULL
		 && strstr(g.gl_pathv[i], ext) == NULL)
		{
			continue;
		}
		if (fmdolder("totp", g.gl_pathv[i]))
			dobuild = true;
		strspushl(&cmd, g.gl_pathv[i]);
	}

	if (dobuild)
		CMDPRC(cmd);

	globfree(&g);
	strsfree(&cmd);
}

char *
mkoutpath(const char *s)
{
	char *p, *buf;

	buf = xmalloc(PATH_MAX);
	buf[0] = 0;

	if (p = getenv("DESTDIR"), p && *p) {
		if (strlcat(buf, p, PATH_MAX) >= PATH_MAX)
			goto toolong;
	}

	p = getenv("PREFIX");
	if (strlcat(buf, p && *p ? p : PREFIX, PATH_MAX) >= PATH_MAX)
		goto toolong;
	if (strlcat(buf, s, PATH_MAX) >= PATH_MAX)
		goto toolong;

	return buf;

toolong:
	errno = ENAMETOOLONG;
	err(1, "$DESTDIR/$PREFIX");
}

void *
xmalloc(size_t n)
{
	void *p = malloc(n);
	if (p == NULL)
		err(1, "malloc");
	return p;
}

char *
xstrdup(const char *s)
{
	char *p = strdup(s);
	if (p == NULL)
		err(1, "strdup");
	return p;
}
