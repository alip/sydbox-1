/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * The following functions are based in part upon systemd:
 *   - truncate_nl()
 *   - read_one_line_file()
 *   - path_is_absolute()
 *   - path_make_absolute()
 *   - readlink_alloc()
 *   which are:
 *   Copyright 2010 Lennart Poettering
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "file.h"

#define NEWLINE "\n\r"

char *truncate_nl(char *s)
{
	assert(s);

	s[strcspn(s, NEWLINE)] = 0;
	return s;
}

int basename_alloc(const char *path, char **buf)
{
	char *c, *bname;

	assert(buf);

	if (!(c = strdup(path)))
		return -ENOMEM;

	bname = basename(c);

	if (!(*buf = strdup(bname))) {
		free(c);
		return -ENOMEM;
	}

	free(c);
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

		if ((n = readlink(path, c, l - 1)) < 0) {
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

	if (!(f = fopen(fn, "r")))
		return -errno;

	if (!(fgets(t, sizeof(t), f))) {
		r = -errno;
		goto finish;
	}

	if (!(c = strdup(t))) {
		r = -ENOMEM;
		goto finish;
	}

	truncate_nl(c);

	*line = c;
	r = 0;

finish:
	fclose(f);
	return r;
}
