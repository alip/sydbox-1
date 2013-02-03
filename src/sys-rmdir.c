/*
 * sydbox/sys-rmdir.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_rmdir(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_write_off(data))
		return 0;

	init_sysinfo(&info);
	info.can_mode |= CAN_NOLINKS;
	info.syd_mode |= SYD_IFBAREDIR;

	return box_check_path(current, name, &info);
}
