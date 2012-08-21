/*
 * sydbox/xfunc.h
 *
 * Copyright (c) 2010, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef XFUNC_H
#define XFUNC_H 1

#include <stddef.h>
#include <pinktrace/compiler.h>

extern void *xmalloc(size_t size)
	PINK_GCC_ATTR((malloc));
extern void *xcalloc(size_t nmemb, size_t size)
	PINK_GCC_ATTR((malloc));
extern void *xrealloc(void *ptr, size_t size);

extern char *xstrdup(const char *src);
extern char *xstrndup(const char *src, size_t n);

extern int xasprintf(char **strp, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 2, 3)));

extern char *xgetcwd(void);

#endif
