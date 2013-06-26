/*
 * sydbox/realpath.c
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon FreeBSD's lib/libc/stdlib/realpath.c which is:
 *   Copyright (c) 2003 Constantin S. Svintsoff <kostik@iclub.nsu.ru>
 * Released under the terms of the 3-clause BSD license
 */

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include "sydconf.h"
#include "bsd-compat.h"
#include "file.h"

struct stat_mode {
	unsigned rmode;
	unsigned nofollow;
	bool last_node;
};

static int stat_mode(const char *path, const struct stat_mode *mode,
		     struct stat *buf)
{
	int r, save_errno;
	struct stat sb, sb_r;

	r = lstat(path, &sb);
	if (r < 0) {
		if (mode->rmode == RPATH_NOLAST && mode->last_node) {
			sb.st_mode = 0;
			goto out;
		}
		return -errno;
	}
	if (S_ISLNK(sb.st_mode)) {
		if (mode->nofollow && mode->last_node) {
			sb.st_mode = 0;
			goto out;
		}

		r = stat(path, &sb_r);
		save_errno = errno;
		utime_reset(path, &sb);

		if (r < 0) {
			if (mode->rmode == RPATH_NOLAST) {
				if (mode->last_node) {
					if (mode->nofollow)
						sb.st_mode = 0;
					goto out;
				} else if (save_errno == ENOENT ||
					   save_errno == ELOOP) {
					sb.st_mode = 0;
					goto out;
				}
			} else { /* if (mode->rmode == RPATH_EXIST) */
				if (mode->nofollow)
					goto out;
			}
			return -save_errno;
		}
	}
out:
	*buf = sb;
	return 0;
}

/*
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 *
 * Take care of side affects like symlink atime update on readlink() etc.
 */
int realpath_mode(const char * restrict path, unsigned mode, char **buf)
{
	struct stat sb;
	struct stat_mode sm;
	char *p, *q, *s;
	size_t left_len, resolved_len;
	unsigned symlinks;
	int r, slen;
	char left[SYDBOX_PATH_MAX], next_token[SYDBOX_PATH_MAX];
	char symlink[SYDBOX_PATH_MAX];

	short flags;
	bool nofollow;
	char *resolved;

	if (!path)
		return -EINVAL;
	if (path[0] == '\0')
		return -ENOENT;
	if (path[0] != '/')
		return -EINVAL;
	if (buf == NULL)
		return -EINVAL;
	flags = mode & ~RPATH_MASK;
	nofollow = !!(flags & RPATH_NOFOLLOW);
	mode &= RPATH_MASK;

	resolved = malloc(sizeof(char) * SYDBOX_PATH_MAX);
	if (!resolved)
		return -ENOMEM;
	r = 0;
	symlinks = 0;
	resolved[0] = '/';
	resolved[1] = '\0';
	if (path[1] == '\0')
		goto out;
	resolved_len = 1;
	left_len = strlcpy(left, path + 1, sizeof(left));
	if (left_len >= sizeof(left) || resolved_len >= SYDBOX_PATH_MAX) {
		free(resolved);
		return -ENAMETOOLONG;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	while (left_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(left, '/');
		s = p ? p : left + left_len;
		if ((size_t)(s - left) >= sizeof(next_token)) {
			free(resolved);
			return -ENAMETOOLONG;
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		left_len -= s - left;
		if (p != NULL)
			memmove(left, s + 1, left_len + 1);
		if (resolved[resolved_len - 1] != '/') {
			if (resolved_len + 1 >= SYDBOX_PATH_MAX) {
				free(resolved);
				return -ENAMETOOLONG;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
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
			sm.rmode = mode;
			sm.nofollow = nofollow;
			sm.last_node = true;
			if ((r = stat_mode(resolved, &sm, &sb)) < 0) {
				free(resolved);
				return r;
			}
			if (sb.st_mode == 0 && mode == RPATH_NOLAST) {
				r = 0;
				break;
			}
			if (!S_ISDIR(sb.st_mode)) {
				free(resolved);
				return -ENOTDIR;
			}
			continue;
		}
		else if (strcmp(next_token, ".") == 0)
			continue;
		else if (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			if (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			continue;
		}

		/*
		 * Append the next path component and lstat() it.
		 */
		resolved_len = strlcat(resolved, next_token, SYDBOX_PATH_MAX);
		if (resolved_len >= SYDBOX_PATH_MAX) {
			free(resolved);
			return -ENAMETOOLONG;
		}

		sm.rmode = mode;
		sm.nofollow = nofollow;
		if (p == NULL || left == NULL || left[strspn(left, "/")] == '\0')
			sm.last_node = true;
		else
			sm.last_node = false;
		if ((r = stat_mode(resolved, &sm, &sb)) < 0) {
			free(resolved);
			return r;
		}
		if (S_ISLNK(sb.st_mode)) {
			if (symlinks++ > SYDBOX_MAXSYMLINKS) {
				free(resolved);
				return -ELOOP;
			}
			if (!nofollow) {
				slen = readlink_copy(resolved, symlink, SYDBOX_PATH_MAX);
				utime_reset(resolved, &sb);
				if (slen < 0) {
					free(resolved);
					return slen; /* negated errno */
				}
				if (symlink[0] == '/') {
					resolved[1] = 0;
					resolved_len = 1;
				} else if (resolved_len > 1) {
					/* Strip the last path component. */
					resolved[resolved_len - 1] = '\0';
					q = strrchr(resolved, '/') + 1;
					*q = '\0';
					resolved_len = q - resolved;
				}
			}

			/*
			 * If there are any path components left, then
			 * append them to symlink. The result is placed
			 * in `left'.
			 */
			if (p != NULL) {
				if (symlink[slen - 1] != '/') {
					if ((size_t)(slen + 1) >= sizeof(symlink)) {
						free(resolved);
						return -ENAMETOOLONG;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				left_len = strlcat(symlink, left, sizeof(symlink));
				if (left_len >= sizeof(left)) {
					free(resolved);
					return -ENAMETOOLONG;
				}
			}
			left_len = strlcpy(left, symlink, sizeof(left));
			if (nofollow && p == NULL) {
				r = 0;
				resolved_len = strlcat(resolved, left, SYDBOX_PATH_MAX);
				break;
			}
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	if (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
out:
	*buf = resolved;
	return r;
}
