/*
 * sydbox/sys-mkdir.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_mkdir(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.can_mode = CAN_ALL_BUT_LAST;
	info.fail_if_exist = true;

	return box_check_path(current, name, &info);
}

int sys_mkdirat(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.fail_if_exist = true;

	return box_check_path(current, name, &info);
}
