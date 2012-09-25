/*
 * sydbox/path.c
 *
 * Path related utilities
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010-2012 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

inline int path_is_absolute(const char *p)
{
	return p[0] == '/';
}

/* Makes every item in the list an absolute path by prepending
 * the prefix, if specified and necessary */
char *path_make_absolute(const char *p, const char *prefix)
{
	char *r;

	if (path_is_absolute(p) || !prefix)
		return strdup(p);

	if (asprintf(&r, "%s/%s", prefix, p) < 0)
		return NULL;

	return r;
}

char *path_kill_slashes(char *path)
{
	char *f, *t;
	bool slash = false;

	/* Removes redundant inner and trailing slashes. Modifies the
	 * passed string in-place.
	 *
	 * ///foo///bar/ becomes /foo/bar
	 */

	for (f = path, t = path; *f; f++) {

		if (*f == '/') {
			slash = true;
			continue;
		}

		if (slash) {
			slash = false;
			*(t++) = '/';
		}

		*(t++) = *f;
	}

	/* Special rule, if we are talking of the root directory, a
	trailing slash is good */

	if (t == path && slash)
		*(t++) = '/';

	*t = 0;
	return path;
}
