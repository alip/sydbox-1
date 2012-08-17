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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_utime(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, name, &info);
}

int sys_utimes(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, name, &info);
}

int sys_utimensat(struct pink_easy_process *current, const char *name)
{
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
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
		log_trace("drop process %s[%lu:%u]",
				data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	init_sysinfo(&info);
	info.at_func = true;
	info.null_ok = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, name, &info);
}

int sys_futimesat(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.null_ok = true;
	info.arg_index = 1;

	return box_check_path(current, name, &info);
}
