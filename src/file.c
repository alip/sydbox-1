/*
 * sydbox/file.c
 *
 * File related utilities
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is
 *   Copyright 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "file.h"

#define NEWLINE "\n\r"

bool empty_line(const char *s)
{
	assert(s);

	return !!(strcspn(s, NEWLINE) == 0);
}

char *truncate_nl(char *s)
{
	assert(s);

	s[strcspn(s, NEWLINE)] = 0;
	return s;
}

int basename_alloc(const char *path, char **buf)
{
	char *c, *bname, *retbuf;

	assert(buf);

	c = strdup(path);
	if (!c)
		return -ENOMEM;

	bname = basename(c);

	retbuf = strdup(bname);
	if (!retbuf) {
		free(c);
		return -ENOMEM;
	}

	free(c);
	*buf = retbuf;
	return 0;
}

/* readlink() wrapper which:
 * - allocates the string itself.
 * - appends a zero-byte at the end.
 */
int readlink_alloc(const char *path, char **buf)
{
	size_t l = 100;

	for (;;) {
		char *c;
		ssize_t n;

		c = malloc(l * sizeof(char));
		if (!c)
			return -ENOMEM;

		n = readlink(path, c, l - 1);
		if (n < 0) {
			int ret = -errno;
			free(c);
			return ret;
		}

		if ((size_t)n < l - 1) {
			c[n] = 0;
			*buf = c;
			return 0;
		}

		free(c);
		l *= 2;
	}
}

int read_one_line_file(const char *fn, char **line)
{
	int r;
	FILE *f;
	char t[LINE_MAX], *c;

	assert(fn);
	assert(line);

	f = fopen(fn, "r");
	if (!f)
		return -errno;

	if (!fgets(t, sizeof(t), f)) {
		r = -errno;
		goto out;
	}

	c = strdup(t);
	if (!c) {
		r = -ENOMEM;
		goto out;
	}

	truncate_nl(c);

	*line = c;
	r = 0;

out:
	fclose(f);
	return r;
}

/* TODO: Use getdents() on Linux for a slight performance gain. */
int empty_dir(const char *dname)
{
	int r;
	DIR *d;

	d = opendir(dname);
	if (!d)
		return -errno;

	r = 0;
	for (unsigned n = 0; readdir(d) != NULL; n++) {
		if (n > 2) {
			r = -ENOTEMPTY;
			break;
		}
	}
	closedir(d);
	return r;
}
