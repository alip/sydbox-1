/*
 * libsyd/file.c
 *
 * file and path utilities
 *
 * Copyright (c) 2015 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU Lesser General Public License v3 (or later)
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static inline int syd_open_path(const char *pathname, int flags)
{
	int fd;

	fd = open(pathname, flags|O_PATH|O_CLOEXEC);
	return (fd >= 0) ? fd : -errno;
}

int syd_opendir(const char *dirname)
{
	return syd_open_path(dirname, O_DIRECTORY);
}

int syd_fchdir(int fd)
{
	if (fchdir(fd) < 0)
		return -errno;
	return 0;
}
