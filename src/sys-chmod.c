/*
 * sydbox/sys-chmod.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_chmod(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, name, &info);
}

int sys_fchmodat(struct pink_easy_process *current, const char *name)
{
	int r;
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	/* Check for AT_SYMLINK_NOFOLLOW */
	if ((r = pink_read_argument(tid, abi, &data->regs, 3, &flags)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_argument(%lu, %d, 3) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -r, strerror(-r));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 3) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -r, strerror(-r));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, name, &info);
}
