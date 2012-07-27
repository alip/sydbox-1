/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
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

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_fcntl(pink_easy_process_t *current, PINK_GCC_ATTR((unused)) const char *name)
{
	long fd, cmd;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_sock_off(data) || !sydbox->config.whitelist_successful_bind)
		return 0;

	/* Read the command */
	if (!pink_read_argument(tid, abi, data->regs, 1, &cmd)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 1): %d(%s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	/* We're interested in two commands:
	 * fcntl(fd, F_DUPFD);
	 * fcntl(fd, F_DUPFD_CLOEXEC);
	 */
	switch (cmd) {
	case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
#endif /* F_DUPFD_CLOEXEC */
		data->args[1] = cmd;
		break;
	default:
		return 0;
	}

	/* Read the file descriptor */
	if (!pink_read_argument(tid, abi, data->regs, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 0) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	data->args[0] = fd;
	return 0;
}

int sysx_fcntl(pink_easy_process_t *current, const char *name)
{
	long retval;
	ht_int64_node_t *old_node, *new_node;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_sock_off(data) || !sydbox->config.whitelist_successful_bind || !data->args[0])
		return 0;

	/* Read the return value */
	if (!pink_read_retval(tid, abi, data->regs, &retval, NULL)) {
		if (errno != ESRCH) {
			warning("pink_read_retval(%lu, %d) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		debug("ignoring failed %s() call for process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"]",
				name, (unsigned long)tid, abi,
				data->comm, data->cwd);
		return 0;
	}

	if (!(old_node = hashtable_find(data->sockmap, data->args[0] + 1, 0))) {
		debug("process:%lu [abi:%d name:\"%s\" cwd:\"%s\"]"
				" duplicated unknown fd:%ld to fd:%ld by %s() call",
				(unsigned long)tid, abi,
				data->comm, data->cwd,
				data->args[0], retval, name);
		return 0;
	}

	if (!(new_node = hashtable_find(data->sockmap, retval + 1, 1)))
		die_errno(-1, "hashtable_find");

	new_node->data = sock_info_xdup(old_node->data);
	info("process:%lu [abi:%d name:\"%s\" cwd:\"%s\"]"
			" duplicated fd:%lu to fd:%lu by %s() call",
			(unsigned long)tid, abi,
			data->comm, data->cwd,
			data->args[0], retval, name);
	return 0;
}
