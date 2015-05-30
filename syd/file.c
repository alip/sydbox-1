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

#include "syd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int syd_fstat(int fd, struct stat *buf)
{
	if (fstat(fd, buf) < 0)
		return -errno;
	return 0;
}

/*
 * Returns -EINVAL: This is not /
 *	   -ENOENT: Does not exist e.g: /.../foo
 *	   0      : This _is_ /
 *	   > 0    : This is an absolute path, skip this many characters till '/'
 * Path must not be empty!
 */
int syd_path_root_check(const char *path)
{
	/* Handle quick cases */
	if (path == NULL)
		return -EINVAL;
	if (path[0] != '/')
		return -EINVAL;
	if (path[1] == '\0')
		return 0;

	/* /../../. is OK but /.../ is not. */
	for (unsigned int i = 1, ndot = 0; path[i] != '\0'; i++) {
		if (path[i] == '.') {
			if (++ndot > 2)
				return -ENOENT;
			continue;
		} else if (path[i] != '/') {
			return (i - 1); /* Absolute path */
		} else if (ndot > 0) {
			ndot = 0;
		}
	}

	return 0;
}

static inline int syd_path_root_alloc(char **buf)
{
	char *rpath;

	rpath = malloc(sizeof(char) * 2);
	if (rpath == NULL)
		return -errno;
	rpath[0] = '/';
	rpath[1] = '\0';
	*buf = rpath;

	return 0;
}

/*
 * Requires absolute path.
 */
int syd_path_stat(const char *path, int mode, bool last_node, struct stat *buf)
{
	int fd, flags, sflags;
	bool nofollow, ignore_noent;
	struct stat sb;

	if (buf == NULL || path == NULL || path[0] != '/')
		return -EINVAL;

	flags = O_NOATIME;
	sflags = AT_EMPTY_PATH|AT_NO_AUTOMOUNT;
	nofollow = mode & ~SYD_REALPATH_MASK & SYD_REALPATH_NOFOLLOW;
	ignore_noent = last_node && (mode & SYD_REALPATH_NOLAST);
	if (nofollow) {
		flags |= O_NOFOLLOW;
		sflags |= AT_SYMLINK_NOFOLLOW;
	}

#define ignore_last_node(n_errno) (ignore_noent && \
				  ((n_errno) == -ENOENT || (n_errno) == -ELOOP))

	fd = syd_open_path(path, flags);
	if (fd < 0) {
		if (ignore_last_node(fd)) {
			sb.st_mode = 0;
			goto out;
		}
		return fd; /* negated errno */
	}

	if (fstatat(fd, "", &sb, sflags) < 0) {
		int save_errno = -errno;
		if (ignore_last_node(save_errno)) {
			sb.st_mode = 0;
			goto out;
		}
		close(fd);
		return save_errno;
	}

	if (!S_ISLNK(sb.st_mode) || (nofollow && last_node))
		goto out;

	close(fd);

	flags &= ~O_NOFOLLOW;
	fd = syd_open_path(path, flags);
	if (fd < 0) {
		if (mode & SYD_REALPATH_NOLAST) {
			if (last_node) {
				if (nofollow)
					sb.st_mode = 0;
				goto out;
			} else if (fd == -ENOENT || fd == -ELOOP) {
				sb.st_mode = 0;
				goto out;
			}
		} else if (nofollow) { /* SYD_REALPATH_EXIST */
			goto out;
		}
		return fd; /* negated errno */
	}
out:
	if (fd >= 0)
		close(fd);
	*buf = sb;
	return 0;
#undef ignore_last_node
}

int syd_realpath_at(int fd, const char *path, char **buf, int mode)
{
	int r, save_fd = -ENOENT;
	char *left = NULL, *rpath = NULL;

	/* Handle (very) quick cases */
	if (path && path[0] == '\0')
		return -ENOENT;

	/* Validate arguments */
	if (buf == NULL)
		return -EINVAL;
	if (fd < 0 && fd != AT_FDCWD)
		return -EINVAL;

	/* Handle quick cases */
	r = syd_path_root_check(path);
	switch (r) {
	case -ENOENT:
		return -ENOENT;
	case 0: /* This is == '/' */
		return syd_path_root_alloc(buf);
	case -EINVAL:
		r = 0;
		break;
	default: /* >0 absolute path */
		path += r;
		r = 0;
		break;
	}

	if (path[0] != '/')
		goto out; /* ignore for now */

#if 0
	if (path[0] == '/') {
	} else {
		r = syd_opendir(".");
		if (r >= 0 || r == -ENOENT)
			save_fd = r;
		else
			return r;

		if ((r = syd_fchdir(fd)) < 0)
			goto out;
	}
#endif

	bool nofollow;
	short flags;
	size_t llen, plen, rlen;

	flags = mode & ~SYD_REALPATH_MASK;
	nofollow = !!(flags & SYD_REALPATH_NOFOLLOW);
	mode &= SYD_REALPATH_MASK;
	plen = strlen(path);

	left = malloc(sizeof(char) * plen);
	if (left == NULL)
		return -errno;
	llen = syd_strlcpy(left, path + 1, sizeof(left));
	if (llen >= sizeof(left)) {
		r = -ENAMETOOLONG; /* Should not happen */
		goto out;
	}

	rpath = malloc(sizeof(char) * (plen + 1));
	if (rpath == NULL) {
		r = -errno;
		goto out;
	}
	rpath[0] = '/';
	rpath[1] = '\0';
	rlen = 1;

	/*
	 * Iterate over path components in `left'.
	 */
	while (llen != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		char *p, *q, *s;
		char *next_token = NULL;
		size_t ntlen;

		p = strchr(left, '/');
		s = p ? p : left + llen;
		if (next_token == NULL) {
			ntlen = (s - left) + 1;
			next_token = malloc(sizeof(char) * ntlen);
			if (next_token == NULL) {
				r = -errno;
				free(next_token);
				goto out;
			}
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		llen -= s - left;
		if (p != NULL)
			memmove(left, s + 1, llen + 1);
		if (rpath[rlen - 1] != '/') {
			if (rlen >= plen) {
				plen += (rlen - plen) > 128 ? (rlen - plen) : 128;
				rpath = realloc(rpath, sizeof(char) * (plen + 1));
				if (rpath == NULL) {
					r = -errno;
					if (next_token != NULL)
						free(next_token);
					goto out;
				}
			}
			rpath[rlen++] = '/';
			rpath[rlen] = '\0';
		}
		if (next_token[0] == '\0') {
			/*
			 * Handle consequential slashes.  The path
			 * before slash shall point to a directory.
			 *
			 * Only the trailing slashes are not covered
			 * by other checks in the loop, but we verify
			 * the prefix for any (rare) "//" or "/\0"
			 * occurrence to not implement lookahead.
			 */
			;
		}
	}

out:
	if (save_fd >= 0) {
		syd_fchdir(save_fd);
		close(save_fd);
	}
	if (left)
		free(left);
	if (r < 0 && rpath != NULL)
		free(rpath);
	return r;
}