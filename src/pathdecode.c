/*
 * sydbox/pathdecode.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include "pathdecode.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <pinktrace/pink.h>
#include "log.h"
#include "proc.h"

/* Decode the path at the given index and place it in buf.
 * Handles panic()
 * Returns:
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 */
int path_decode(syd_proc_t *current, unsigned arg_index, char **buf)
{
	int r;
	ssize_t count_read;
	long addr;
	char path[SYDBOX_PATH_MAX];

	assert(current);
	assert(buf);

	if ((r = syd_read_argument(current, arg_index, &addr)) < 0)
		return r;

	/* syd_read_string() handles panic() and partial reads */
	count_read = syd_read_string(current, addr, path, SYDBOX_PATH_MAX);
	if (count_read < 0) {
		if (errno == EFAULT) {
			*buf = NULL;
			return 0;
		}
		return -errno;
	}
	*buf = xstrdup(path);
	return 0;
}

/*
 * Resolve the prefix of an at-suffixed function.
 * Handles panic()
 * Returns:
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 */
int path_prefix(syd_proc_t *current, unsigned arg_index, char **buf)
{
	int r;
	long fd;
	char *prefix = NULL;
	pid_t pid = GET_PID(current);

	if ((r = pink_read_argument(current->pink, arg_index, &fd)) < 0) {
		if (r == ESRCH) {
			log_trace("read_argument(pid:%u, index:%u) failed (errno:%d %s)",
				  pid, arg_index, -r, strerror(-r));
			log_trace("drop process %s[%u]", current->comm,
				  pid);
			return -ESRCH;
		}
		log_warning("read_argument(pid:%u, index:%u) failed (errno:%d %s)",
			    pid, arg_index, -r, strerror(-r));
		return panic(current);
	}

	r = 0;
	if (fd == AT_FDCWD) {
		*buf = NULL;
	} else if (fd < 0) {
		log_check("invalid fd=%ld, skip /proc read", fd);
		*buf = NULL;
		r = -EBADF;
	} else {
		if ((r = proc_fd(pid, fd, &prefix)) < 0) {
			log_warning("readlink /proc/%u/fd/%ld failed (errno:%d %s)",
				    pid, fd, -r, strerror(-r));
			if (r == -ENOENT)
				r = -EBADF; /* correct errno */
		} else {
			*buf = prefix;
		}
	}

	if (r == 0)
		log_check("fd=%ld maps to prefix=`%s'", fd,
			  fd == AT_FDCWD ? "AT_FDCWD" : prefix);

	return r;
}
