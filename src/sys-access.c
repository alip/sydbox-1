/*
 * sydbox/sys-access.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_access(struct pink_easy_process *current, const char *name)
{
	int r;
	long mode;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_exec_off(data)
	    && sandbox_read_off(data)
	    && sandbox_write_off(data))
		return 0;

	if (!pink_read_argument(tid, abi, &data->regs, 1, &mode)) {
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

	if (!((mode & R_OK) && sandbox_read_off(data))
	    && !((mode & W_OK) && sandbox_write_off(data))
	    && !((mode & X_OK) && sandbox_exec_off(data)))
		return 0;

	init_sysinfo(&info);
	info.safe = true;
	info.deny_errno = EACCES;

	r = 0;
	if (!sandbox_write_off(data) && mode & W_OK)
		r = box_check_path(current, name, &info);

	if (!r && !data->deny && !sandbox_read_off(data) && mode & R_OK) {
		info.access_mode = sandbox_read_deny(data)
				   ? ACCESS_WHITELIST
				   : ACCESS_BLACKLIST;
		info.access_list = sandbox_read_deny(data)
				   ? &data->config.whitelist_read
				   : &data->config.blacklist_read;
		info.access_filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !sandbox_exec_off(data) && mode & X_OK) {
		info.access_mode = sandbox_exec_deny(data)
				   ? ACCESS_WHITELIST
				   : ACCESS_BLACKLIST;
		info.access_list = sandbox_exec_deny(data)
				   ? &data->config.whitelist_exec
				   : &data->config.blacklist_exec;
		info.access_filter = &sydbox->config.filter_exec;
		r = box_check_path(current, name, &info);
	}

	return r;
}

int sys_faccessat(struct pink_easy_process *current, const char *name)
{
	int r;
	long mode, flags;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_exec_off(data)
	    && sandbox_read_off(data)
	    && sandbox_write_off(data))
		return 0;

	/* Check mode argument first */
	if (!pink_read_argument(tid, abi, &data->regs, 2, &mode)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %d, 2) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 2) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	if (!((mode & R_OK) && sandbox_read_off(data))
	    && !((mode & W_OK) && sandbox_write_off(data))
	    && !((mode & X_OK) && sandbox_exec_off(data)))
		return 0;

	/* Check for AT_SYMLINK_NOFOLLOW */
	if (!pink_read_argument(tid, abi, &data->regs, 3, &flags)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %d, 3) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 3) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.safe = true;
	info.deny_errno = EACCES;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	r = 0;
	if (!sandbox_write_off(data) && mode & W_OK)
		r = box_check_path(current, name, &info);

	if (!r && !data->deny && !sandbox_read_off(data) && mode & R_OK) {
		info.access_mode = sandbox_read_deny(data)
				   ? ACCESS_WHITELIST
				   : ACCESS_BLACKLIST;
		info.access_list = sandbox_read_deny(data)
				   ? &data->config.whitelist_read
				   : &data->config.blacklist_read;
		info.access_filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !sandbox_exec_off(data) && mode & X_OK) {
		info.access_mode = sandbox_exec_deny(data)
				   ? ACCESS_WHITELIST
				   : ACCESS_BLACKLIST;
		info.access_list = sandbox_exec_deny(data)
				   ? &data->config.whitelist_exec
				   : &data->config.blacklist_exec;
		info.access_filter = &sydbox->config.filter_exec;
		r = box_check_path(current, name, &info);
	}

	return r;
}
