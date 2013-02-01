/*
 * sydbox/sys-mount.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mount.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_mount(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;

	return box_check_path(current, name, &info);
}

int sys_umount(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, name, &info);
}

int sys_umount2(struct pink_easy_process *current, const char *name)
{
	int r;
#ifdef UMOUNT_NOFOLLOW
	long flags;
	pid_t tid;
	enum pink_abi abi;
#endif
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
#ifdef UMOUNT_NOFOLLOW
	/* Check for UMOUNT_NOFOLLOW */
	tid = pink_easy_process_get_tid(current);
	abi = pink_easy_process_get_abi(current);
	if ((r = pink_read_argument(tid, abi, &data->regs, 1, &flags)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_argument(%lu, %d, 1) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -r, strerror(-r));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 1) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -r, strerror(-r));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);

		return PINK_EASY_CFLAG_DROP;
	}
	if (flags & UMOUNT_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;
#endif /* UMOUNT_NOFOLLOW */

	return box_check_path(current, name, &info);
}
