/*
 * sydbox/xfunc.c
 *
 * Copyright (c) 2010, 2012, 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydconf.h"
#include "xfunc.h"
#include "dump.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pinktrace/pink.h>

/* abort function. */
static void (*abort_func)(int sig);

PINK_GCC_ATTR((noreturn))
static void syd_abort(int how) /* SIGTERM == exit(1), SIGABRT == abort() */
{
	if (abort_func)
		abort_func(SIGTERM);
	switch (how) {
	case SIGABRT:
		abort();
	case SIGTERM:
	default:
		exit(1);
	}
}

void syd_abort_func(void (*func)(int))
{
	abort_func = func;
}

void assert_(const char *expr, const char *func,
	     const char *file, size_t line)
{
	fprintf(stderr, "Assertion '%s' failed at %s:%zu, function %s()",
		expr, file, line, func);

	dump(DUMP_ASSERT, expr, file, line, func);
	dump(DUMP_CLOSE);

	syd_abort(SIGABRT);
}

void assert_not_reached_(const char *func, const char *file, size_t line)
{
	fprintf(stderr, "Code must not be reached at %s:%zu, function %s()",
		file, line, func);

	dump(DUMP_CLOSE);

	syd_abort(SIGABRT);
}

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);

	syd_abort(SIGTERM);
}

void die_errno(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, " (errno:%d|%s| %s)\n",
		errno, pink_name_errno(errno, 0), strerror(errno));

	syd_abort(SIGTERM);
}

void *xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		die_errno("malloc");

	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ptr = calloc(nmemb, size);
	if (!ptr)
		die_errno("calloc");

	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	void *nptr;

	nptr = realloc(ptr, size);
	if (!nptr)
		die_errno("realloc");

	return nptr;
}

char *xstrdup(const char *src)
{
	char *dest;

	dest = strdup(src);
	if (!dest)
		die_errno("strdup");

	return dest;
}

char *xstrndup(const char *src, size_t n)
{
	char *dest;

	dest = strndup(src, n);
	if (!dest)
		die_errno("strndup");

	return dest;
}

int xasprintf(char **strp, const char *fmt, ...)
{
	int r;
	char *dest;
	va_list ap;

	assert(strp);

	va_start(ap, fmt);
	r = vasprintf(&dest, fmt, ap);
	va_end(ap);

	if (r == -1) {
		errno = ENOMEM;
		die_errno("vasprintf");
	}

	*strp = dest;
	return r;
}

char *xgetcwd(void)
{
	char *cwd;
#ifdef _GNU_SOURCE
	cwd = get_current_dir_name();
#else
	cwd = xmalloc(sizeof(char) * (PATH_MAX + 1));
	cwd = getcwd(cwd, PATH_MAX + 1);
#endif
	if (!cwd)
		die_errno("getcwd");
	return cwd;
}
