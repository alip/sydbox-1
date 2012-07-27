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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_access(pink_easy_process_t *current, const char *name)
{
	int r;
	long mode;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (SANDBOX_EXEC_OFF(data) && SANDBOX_READ_OFF(data) && SANDBOX_WRITE_OFF(data))
		return 0;

	if (!pink_read_argument(tid, abi, data->regs, 1, &mode)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 1) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (!((mode & R_OK) && SANDBOX_READ_OFF(data))
		&& !((mode & W_OK) && SANDBOX_WRITE_OFF(data))
		&& !((mode & X_OK) && SANDBOX_EXEC_OFF(data)))
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.resolv = true;
	info.safe = true;
	info.deny_errno = EACCES;

	r = 0;
	if (!SANDBOX_WRITE_OFF(data) && mode & W_OK) {
		info.whitelisting = SANDBOX_WRITE_DENY(data);
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !SANDBOX_READ_OFF(data) && mode & R_OK) {
		info.whitelisting = SANDBOX_READ_DENY(data);
		info.wblist = SANDBOX_READ_DENY(data) ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !SANDBOX_EXEC_OFF(data) && mode & X_OK) {
		info.whitelisting = SANDBOX_EXEC_DENY(data);
		info.wblist = SANDBOX_EXEC_DENY(data) ? &data->config.whitelist_exec : &data->config.blacklist_exec;
		info.filter = &sydbox->config.filter_exec;
		r = box_check_path(current, name, &info);
	}

	return r;
}

int sys_faccessat(pink_easy_process_t *current, const char *name)
{
	int r;
	long mode, flags;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (SANDBOX_EXEC_OFF(data) && SANDBOX_READ_OFF(data) && SANDBOX_WRITE_OFF(data))
		return 0;

	/* Check mode argument first */
	if (!pink_read_argument(tid, abi, data->regs, 2, &mode)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 2) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (!((mode & R_OK) && SANDBOX_READ_OFF(data))
		&& !((mode & W_OK) && SANDBOX_WRITE_OFF(data))
		&& !((mode & X_OK) && SANDBOX_EXEC_OFF(data)))
		return 0;

	/* Check for AT_SYMLINK_NOFOLLOW */
	if (!pink_read_argument(tid, abi, data->regs, 3, &flags)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 3): %d(%s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sys_info_t));
	info.at     = true;
	info.index  = 1;
	info.resolv = !(flags & AT_SYMLINK_NOFOLLOW);
	info.safe   = true;
	info.deny_errno = EACCES;

	r = 0;
	if (!SANDBOX_WRITE_OFF(data) && mode & W_OK) {
		info.whitelisting = SANDBOX_WRITE_DENY(data);
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !SANDBOX_READ_OFF(data) && mode & R_OK) {
		info.whitelisting = SANDBOX_READ_DENY(data);
		info.wblist = SANDBOX_READ_DENY(data) ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !SANDBOX_EXEC_OFF(data) && mode & X_OK) {
		info.whitelisting = SANDBOX_EXEC_DENY(data);
		info.wblist = SANDBOX_EXEC_DENY(data) ? &data->config.whitelist_exec : &data->config.blacklist_exec;
		info.filter = &sydbox->config.filter_exec;
		r = box_check_path(current, name, &info);
	}

	return r;
}
