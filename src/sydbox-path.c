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
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 * >0     : PINK_EASY_CFLAG* flags
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

	if (!pink_read_argument(tid, abi, &data->regs, ind, &addr))
		goto fail;
	if (!pink_read_string(tid, abi, addr, path, SYDBOX_PATH_MAX))
		goto fail;
	path[SYDBOX_PATH_MAX-1] = '\0';
	*buf = xstrdup(path);
	return 0;
fail:
	if (errno == EFAULT) {
		debug("read_string(%lu, %d, %u) returned -EFAULT",
				(unsigned long)tid, abi, ind);
		*buf = NULL;
		return -EFAULT;
	}
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
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 * >0     : PINK_EASY_CFLAG* flags
 */
int path_prefix(struct pink_easy_process *current, unsigned arg_index, char **buf)
{
	int r;
	long fd;
	char *prefix;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	debug("path_prefix: %s[%lu:%u] arg_index:%u",
			data->comm, 
			(unsigned long)tid, abi,
			arg_index);

	if (!pink_read_argument(tid, abi, &data->regs, arg_index, &fd)) {
		if (errno != ESRCH) {
			warning("path_prefix: read argument:%u failed (errno:%d %s)",
					arg_index, errno, strerror(errno));
			return panic(current);
		}
		notice("path_prefix: read argument:%u failed (errno:%d %s)",
				arg_index, errno, strerror(errno));
		notice("path_prefix: drop process %s[%lu:%u]",
				data->comm,
				(unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	if (fd != AT_FDCWD) {
		if ((r = proc_fd(tid, fd, &prefix)) < 0) {
			warning("path_prefix: readlink /proc/%lu/fd/%ld failed (errno:%d %s)",
					fd,
					(unsigned long)tid,
					-r, strerror(-r));
			if (r == -ENOENT)
				r = -EBADF; /* correct errno */
			return r;
		}
		*buf = prefix;
	} else {
		*buf = NULL;
	}

	debug("path_prefix: fd:%ld is %s", fd, prefix ? prefix : "AT_FDCWD");
	return 0;
}
