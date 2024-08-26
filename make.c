#include <assert.h>
#include <getopt.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBS_NO_THREADS
#include "cbs.h"

static void cc(void *);
static void ld(void);
static int globerr(const char *, int);

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
	"-fomit-frame-pointer",
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
	        "Usage: %s [-p generic|arm64|x64] [-fSr]\n"
	        "       %s clean\n",
	        argv0, argv0);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	cbsinit(argc, argv);
	rebuild();

	argv0 = argv[0];

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
			oflag = strdup(optarg);
			assert(oflag != NULL);
			break;
		case 'p':
			if (strcmp(optarg, "generic") == 0
			 || strcmp(optarg, "arm64")   == 0
			 || strcmp(optarg, "x64")     == 0)
			{
				pflag = strdup(optarg);
				assert(pflag != NULL);
			} else {
				fprintf(stderr, "%s: invalid profile -- '%s'\n", argv0, optarg);
				usage();
			}
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
		if (strcmp(argv[0], "clean") != 0) {
			fprintf(stderr, "%s: invalid subcommand -- '%s'\n", argv0, *argv);
			usage();
		}
		struct strs cmd = {0};
		strspushl(&cmd, "find", ".",
			"(",
				"-name", "totp",
				"-or", "-name", "totp-*",
				"-or", "-name", "*.o",
			")", "-delete"
		);
		cmdput(cmd);
		return cmdexec(cmd);
	}

	glob_t g;
	assert(glob("src/*.c", 0, globerr, &g) == 0);

	char *ext = malloc(strlen(pflag) + sizeof("-.c"));
	assert(ext != NULL);
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
	else {
		strspushenv(&cmd, "CFLAGS", cflags_dbg, lengthof(cflags_dbg));
		if (strstr(arg, "-x64.c") != NULL)
			strspushl(&cmd, "-msha", "-mssse3");
	}
	if (strstr(arg, "-arm64.c") != NULL)
		strspushl(&cmd, "-march=native+crypto");
	if (!Sflag)
		strspushl(&cmd, "-fsanitize=address,undefined");
	strspushl(&cmd, "-o", dst, "-c", src);

	cmdput(cmd);
	cmdexec(cmd);
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

	assert(glob("src/*.o", 0, globerr, &g) == 0);

	char *ext = malloc(strlen(pflag) + sizeof("-.o"));
	assert(ext != NULL);
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

	if (dobuild) {
		cmdput(cmd);
		cmdexec(cmd);
	}

	globfree(&g);
	strsfree(&cmd);
}

int
globerr(const char *s, int e)
{
	fprintf(stderr, "glob: %s: %s\n", s, strerror(e));
	exit(EXIT_FAILURE);
}
