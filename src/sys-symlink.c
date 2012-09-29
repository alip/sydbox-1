/*
 * sydbox/sys-symlink.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_symlink(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST | CAN_NOLINKS;
	info.syd_mode = SYD_IFNONE;

	return box_check_path(current, name, &info);
}

int sys_symlinkat(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 2;
	info.can_mode = CAN_ALL_BUT_LAST | CAN_NOLINKS;
	info.syd_mode = SYD_IFNONE;

	return box_check_path(current, name, &info);
}
