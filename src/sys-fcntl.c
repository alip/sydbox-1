/*
 * sydbox/sys-fcntl.h
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#include "sydbox-defs.h"

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_fcntl(struct pink_easy_process *current, const char *name)
{
	long fd, cmd;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data)
	    || !sydbox->config.whitelist_successful_bind)
		return 0;

	/* Read the command */
	if (!pink_read_argument(tid, abi, &data->regs, 1, &cmd)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %d, 1) failed"
					" (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 1) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
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
	if (!pink_read_argument(tid, abi, &data->regs, 0, &fd)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %d, 0) failed"
					" (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 0) failed (errno:%d %s)",
			  (unsigned long)tid, abi, errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
				(unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	data->args[0] = fd;
	return 0;
}

int sysx_fcntl(struct pink_easy_process *current, const char *name)
{
	long retval;
	ht_int64_node_t *old_node, *new_node;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data)
	    || !sydbox->config.whitelist_successful_bind
	    || !data->args[0])
		return 0;

	/* Read the return value */
	if (!pink_read_retval(tid, abi, &data->regs, &retval, NULL)) {
		if (errno != ESRCH) {
			log_warning("read_retval(%lu, %d) failed (errno:%d %s)",
				    (unsigned long)tid, abi,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_retval(%lu, %d) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]",
			  data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		log_trace("ignore failed %s() call for process %s[%lu:%u]",
			  name, data->comm, (unsigned long)tid, abi);
		return 0;
	}

	if (!(old_node = hashtable_find(data->sockmap, data->args[0] + 1, 0))) {
		log_check("process %s[%lu:%u] duplicated unknown fd:%ld to fd:%ld",
			  data->comm, (unsigned long)tid, abi,
			  data->args[0], retval);
		return 0;
	}

	if (!(new_node = hashtable_find(data->sockmap, retval + 1, 1)))
		die_errno("hashtable_find");

	new_node->data = sockinfo_xdup(old_node->data);
	log_check("process %s[%lu:%u] duplicated fd:%ld to fd:%ld",
		  data->comm, (unsigned long)tid, abi,
		  data->args[0], retval);
	return 0;
}
