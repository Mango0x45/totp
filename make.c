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

#define NOB_IMPLEMENTATION
#include "nob.h"

#define PREFIX "/usr/local"

#define streq(x, y) (strcmp(x, y) == 0)
#define CMDPRC(c)                                                              \
	do {                                                                       \
		if (!cmd_run_sync(c))                                              \
			errx(EXIT_FAILURE, "%s terminated with an error", c.items[0]);     \
		c.count = 0;                                                           \
	} while (false)

static void cc(void *);
static void ld(void);
static char *mkoutpath(const char *);
static char *xstrdup(const char *);
static void *xmalloc(size_t);
static char *swpext(const char *, const char *);
static bool binexists(const char *);
static void append_env_or_default(Nob_Cmd *, const char *,
                                  const char **, size_t);

static const char *warnings[] = {
	"-Wall",
	"-Wextra",
	"-Wpedantic",
	"-Wno-parentheses",
};

static const char *cflags_all[] = {
	"-std=c11",
#if __GLIBC__
	"-D_GNU_SOURCE",
#endif
};

static const char *cflags_dbg[] = {
	"-g3",
	"-ggdb3",
	"-O0",
};

static const char *cflags_rls[] = {
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
	GO_REBUILD_URSELF(argc, argv);

	argv0 = basename(argv[0]);

	int opt;
	static const struct option longopts[] = {
		{"force",		 no_argument,		0, 'f'},
		{"no-sanitizer", no_argument,		0, 'S'},
		{"output",		 required_argument, 0, 'o'},
		{"profile",		 required_argument, 0, 'p'},
		{"release",		 no_argument,		0, 'r'},
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
		Nob_Cmd cmd = {0};

		if (streq(argv[0], "clean")) {
			cmd_append(&cmd, "find", ".",
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

			cmd_append(&cmd, "mkdir", "-p", bin, man);
			CMDPRC(cmd);

			const char *stripprg = binexists("strip") ? "strip"
			                     : binexists("llvm-strip") ? "llvm-strip"
			                     : NULL;
			if (stripprg != NULL) {
				cmd_append(&cmd, stripprg, "--strip-all", "totp");
				CMDPRC(cmd);
			}

			cmd_append(&cmd, "cp", "totp", bin);
			CMDPRC(cmd);
			cmd_append(&cmd, "cp", "totp.1", man);
			CMDPRC(cmd);

			free(bin);
			free(man);
		} else {
			fprintf(stderr, "%s: invalid subcommand -- '%s'\n", argv0, *argv);
			usage();
		}

		cmd_free(cmd);
		return EXIT_SUCCESS;
	}

	glob_t g;
	if (glob("src/*.c", 0, NULL, &g) != 0)
		errx(EXIT_FAILURE, "glob: failed to glob");

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

	free(ext);
	globfree(&g);
	ld();

	return EXIT_SUCCESS;
}

void cc(void *arg)
{
	Nob_Cmd cmd = {0};
	char *src = arg;
	char *dst = swpext(src, "o");

	if (!fflag && !needs_rebuild1(dst, src))
		goto out;

	const char *cc_env = getenv("CC");
	cmd_append(&cmd, cc_env && *cc_env ? cc_env : "cc");

	for (size_t i = 0; i < ARRAY_LEN(cflags_all); i++)
		cmd_append(&cmd, cflags_all[i]);

	if (rflag) {
		append_env_or_default(&cmd, "CFLAGS", cflags_rls,
		                      ARRAY_LEN(cflags_rls));
	} else {
		append_env_or_default(&cmd, "CFLAGS", cflags_dbg,
		                      ARRAY_LEN(cflags_dbg));
	}

	if (strstr(src, "-x64.c") != NULL)
		cmd_append(&cmd, "-msha", "-mssse3");
	if (strstr(src, "-arm64.c") != NULL)
		cmd_append(&cmd, "-march=native+crypto");

	if (!Sflag)
		cmd_append(&cmd, "-fsanitize=address,undefined");

	cmd_append(&cmd, "-o", dst, "-c", src);

	CMDPRC(cmd);
	cmd_free(cmd);
out:
	free(dst);
}

void
ld(void)
{
	glob_t g;
	bool dobuild = fflag;
	Nob_Cmd cmd = {0};

	const char *cc_env = getenv("CC");
	cmd_append(&cmd, cc_env && *cc_env ? cc_env : "cc");

	for (size_t i = 0; i < ARRAY_LEN(cflags_all); i++)
		cmd_append(&cmd, cflags_all[i]);

	if (rflag) {
		append_env_or_default(&cmd, "CFLAGS", cflags_rls,
		                      ARRAY_LEN(cflags_rls));
	} else {
		append_env_or_default(&cmd, "CFLAGS", cflags_dbg,
		                      ARRAY_LEN(cflags_dbg));
	}

	if (!Sflag)
		cmd_append(&cmd, "-fsanitize=address,undefined");

	cmd_append(&cmd, "-o", oflag);

	assert(glob("src/*.o", 0, NULL, &g) == 0);

	char *ext = xmalloc(strlen(pflag) + sizeof("-.o"));
	sprintf(ext, "-%s.o", pflag);

	for (size_t i = 0; i < g.gl_pathc; i++) {
		if (strchr(g.gl_pathv[i], '-') != NULL
		 && strstr(g.gl_pathv[i], ext) == NULL)
		{
			continue;
		}
		if (needs_rebuild1(oflag, g.gl_pathv[i]))
			dobuild = true;

		cmd_append(&cmd, g.gl_pathv[i]);
	}

	if (dobuild)
		CMDPRC(cmd);

	free(ext);
	globfree(&g);
	cmd_free(cmd);
}

char *
mkoutpath(const char *s)
{
	Nob_String_Builder sb = {0};

	const char *destdir = getenv("DESTDIR");
	if (destdir && *destdir)
		sb_append_cstr(&sb, destdir);

	const char *prefix = getenv("PREFIX");
	sb_append_cstr(&sb, prefix && *prefix ? prefix : PREFIX);
	sb_append_cstr(&sb, s);
	sb_append_null(&sb);

	char *res = xstrdup(sb.items);
	sb_free(sb);
	return res;
}

char *
swpext(const char *path, const char *ext)
{
	Nob_String_Builder sb = {0};
	const char *dot = strrchr(path, '.');

	if (!dot)
		sb_append_cstr(&sb, path);
	else
		sb_append_buf(&sb, path, dot - path);

	sb_append_cstr(&sb, ".");
	sb_append_cstr(&sb, ext);
	sb_append_null(&sb);

	char *res = xstrdup(sb.items);
	sb_free(sb);
	return res;
}

bool
binexists(const char *prg)
{
	Nob_String_Builder sb = {0};
	sb_append_cstr(&sb, "command -v ");
	sb_append_cstr(&sb, prg);
	sb_append_cstr(&sb, " >/dev/null 2>&1");
	sb_append_null(&sb);

	bool exists = (system(sb.items) == 0);
	sb_free(sb);
	return exists;
}

void *
xmalloc(size_t n)
{
	void *p = malloc(n);
	if (p == NULL)
		err(EXIT_FAILURE, "malloc");
	return p;
}

char *
xstrdup(const char *s)
{
	char *p = strdup(s);
	if (p == NULL)
		err(EXIT_FAILURE, "strdup");
	return p;
}

void
append_env_or_default(Nob_Cmd *cmd, const char *ev,
                      const char **defs, size_t ndefs)
{
	const char *val = getenv(ev);
	if (val && *val) {
		char *val_copy = xstrdup(val);
		char *p = strtok(val_copy, " \t");
		while (p) {
			cmd_append(cmd, xstrdup(p));
			p = strtok(NULL, " \t");
		}
		free(val_copy);
	} else {
		for (size_t i = 0; i < ndefs; i++)
			cmd_append(cmd, defs[i]);
	}
}
