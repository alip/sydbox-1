/*
 * sydbox/sys-link.c
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

int sys_link(struct pink_easy_process *current, const char *name)
{
	int r;
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	/*
	 * POSIX.1-2001 says that link() should dereference oldpath if it is a
	 * symbolic link. However, since kernel 2.0, Linux does not do
	 * so: if  oldpath is a symbolic link, then newpath is created as a
	 * (hard) link to the same symbolic link file (i.e., newpath becomes a
	 * symbolic link to the same file that oldpath refers to). Some other
	 * implementations behave in the same manner as Linux.
	 * POSIX.1-2008 changes the specification of link(), making it
	 * implementation-dependent whether or not oldpath is dereferenced if
	 * it is a symbolic link.
	 */
	info.can_mode |= CAN_NOLINKS;

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.arg_index = 1;
		info.can_mode = CAN_ALL_BUT_LAST;
		info.syd_mode = SYD_STAT_NOEXIST;
		return box_check_path(current, name, &info);
	}

	return r;
}

int sys_linkat(struct pink_easy_process *current, const char *name)
{
	int r;
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	/* Check for AT_SYMLINK_FOLLOW */
	if ((r = pink_read_argument(tid, abi, &data->regs, 4, &flags)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_argument(%lu, %d, 4) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -r, strerror(-r));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 4) failed"
			  " (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -r, strerror(-r));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (!(flags & AT_SYMLINK_FOLLOW))
		info.can_mode |= CAN_NOLINKS;

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.arg_index = 3;
		info.can_mode &= ~CAN_MODE_MASK;
		info.can_mode |= CAN_ALL_BUT_LAST;
		info.syd_mode = SYD_STAT_NOEXIST;
		return box_check_path(current, name, &info);
	}

	return r;
}
