/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
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

#include "sydbox-defs.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"

/* Decode the path at the given index and place it in buf.
 * Handles panic() itself.
 * Returns:
 * -1 : System call must be denied.
 *  0 : Successful run
 * >0 : PINK_EASY_CFLAG* flags
 */
int path_decode(struct pink_easy_process *current, unsigned ind, char **buf)
{
	long addr;
	char path[SYDBOX_PATH_MAX];
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	assert(current);
	assert(buf);

	if (!pink_read_argument(tid, abi, data->regs, ind, &addr))
		goto fail;
	path[0] = '\0';
	if (!pink_read_string(tid, abi, addr, path, SYDBOX_PATH_MAX))
		goto fail;
	if (path[0] == '\0') {
		debug("read_string(%lu, %d, %u) returned NULL",
				(unsigned long)tid, abi, ind);
		errno = EFAULT;
		*buf = NULL;
		return -1;
	} else {
		path[SYDBOX_PATH_MAX-1] = '\0';
		*buf = xstrdup(path);
		return 0;
	}
fail:
	if (errno != ESRCH) {
		warning("read_string(%lu, %d, %u) failed (errno:%d %s)",
				(unsigned long)tid, abi,
				ind, errno, strerror(errno));
		return panic(current);
	}
	debug("read_string(%lu, %d, %u) failed (errno:%d %s)",
			(unsigned long)tid, abi,
			ind, errno, strerror(errno));
	debug("dropping process:%lu"
			" [abi:%d name:\"%s\" cwd:\"%s\"]"
			" from process tree",
			(unsigned long)tid, abi,
			data->comm, data->cwd);
	return PINK_EASY_CFLAG_DROP;
}

/*
 * Resolve the prefix of an at-suffixed function.
 * Handles panic() itself.
 * Returns:
 * -1 : System call must be denied.
 *  0 : Successful run
 * >0 : PINK_EASY_CFLAG* flags
 */
int path_prefix(struct pink_easy_process *current, unsigned ind, char **buf)
{
	int r;
	long fd;
	char *prefix;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!pink_read_argument(tid, abi, data->regs, ind, &fd)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, %u) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					ind, errno, strerror(errno));
			return panic(current);
		}
		debug("pink_read_argument(%lu, %d, %u) failed (errno:%d %s)",
				(unsigned long)tid, abi,
				ind, errno, strerror(errno));
		debug("dropping process:%lu [abi:%d name:\"%s\" cwd:\"%s\"] from process tree",
				(unsigned long)tid, abi,
				data->comm, data->cwd);
		return PINK_EASY_CFLAG_DROP;
	}

	if (fd != AT_FDCWD) {
		if ((r = proc_fd(tid, fd, &prefix)) < 0) {
			warning("proc_fd(%lu, %ld) failed (errno:%d %s)",
					(unsigned long)tid, fd,
					-r, strerror(-r));
			errno = r == -ENOENT ? EBADF : -r;
			return -1;
		}
		*buf = prefix;
	}
	else
		*buf = NULL;

	return 0;
}
