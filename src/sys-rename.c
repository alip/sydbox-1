/*
 * sydbox/sys-rename.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_rename(struct pink_easy_process *current, const char *name)
{
	int r;
	mode_t mode;
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.can_mode = CAN_NOLINKS;
	info.ret_mode = &mode;

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.arg_index = 1;
		info.can_mode &= ~CAN_MODE_MASK;
		info.can_mode |= CAN_ALL_BUT_LAST;
		if (S_ISDIR(mode)) {
			/* oldpath specifies a directory.
			 * In this case, newpath must either not exist,
			 * or it must specify an empty directory.
			 */
			info.syd_mode |= SYD_STAT_EMPTYDIR;
		}
		info.ret_mode = NULL;
		return box_check_path(current, name, &info);
	}

	return r;
}

int sys_renameat(struct pink_easy_process *current, const char *name)
{
	int r;
	mode_t mode;
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = CAN_NOLINKS;
	info.ret_mode = &mode;

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.arg_index = 3;
		info.can_mode &= ~CAN_MODE_MASK;
		info.can_mode |= CAN_ALL_BUT_LAST;
		if (S_ISDIR(mode)) {
			/* oldpath specifies a directory.
			 * In this case, newpath must either not exist,
			 * or it must specify an empty directory.
			 */
			info.syd_mode |= SYD_STAT_EMPTYDIR;
		}
		info.ret_mode = NULL;
		return box_check_path(current, name, &info);
	}

	return r;
}
