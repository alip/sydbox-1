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

int sys_unlink(struct pink_easy_process *current, const char *name)
{
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_write_off(data))
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.whitelisting = sandbox_write_deny(data);

	return box_check_path(current, name, &info);
}

int sys_unlinkat(struct pink_easy_process *current, const char *name)
{
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (sandbox_write_off(data))
		return 0;

	/* If AT_REMOVEDIR flag is set in the third argument, unlinkat()
	 * behaves like rmdir(2), otherwise it behaves like unlink(2).
	 * The difference between the two system calls is, the former resolves
	 * symbolic links, whereas the latter doesn't.
	 */
	if (!pink_read_argument(tid, abi, &data->regs, 2, &flags)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 2) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sys_info_t));
	info.at           = true;
	info.arg_index    = 1;
	info.resolve      = !!(flags & AT_REMOVEDIR);
	info.whitelisting = sandbox_write_deny(data);

	return box_check_path(current, name, &info);
}
