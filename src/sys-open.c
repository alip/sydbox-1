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

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

static inline bool open_wr_check(long flags, enum create_mode *create, bool *resolv)
{
	enum create_mode c;
	bool r;

	assert(create);
	assert(resolv);

	r = true;
	c = flags & O_CREAT ? MAY_CREATE : NO_CREATE;
	if (flags & O_EXCL) {
		if (c == NO_CREATE) {
			/* Quoting open(2):
			 * In general, the behavior of O_EXCL is undefined if
			 * it is used without O_CREAT.  There is one exception:
			 * on Linux 2.6 and later, O_EXCL can be used without
			 * O_CREAT if pathname refers to a block device. If
			 * the block device is in use by the system (e.g.,
			 * mounted), open() fails.
			 */
			/* void */;
		}
		else {
			/* Two things to mention here:
			 * - If O_EXCL is specified in conjunction with
			 *   O_CREAT, and pathname already exists, then open()
			 *   will fail.
			 * - When both O_CREAT and O_EXCL are specified,
			 *   symbolic links are not followed.
			 */
			c = MUST_CREATE;
			r = false;
		}
	}

	*create = c;
	*resolv = r;

	/* `unsafe' flag combinations:
	 * - O_RDONLY | O_CREAT
	 * - O_WRONLY
	 * - O_RDWR
	 */
	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		if (flags & O_CREAT)
			return true;
		break;
	case O_WRONLY:
	case O_RDWR:
		return true;
	}

	return false;
}

int sys_open(pink_easy_process_t *current, const char *name)
{
	int r;
	bool resolv, wr;
	enum create_mode create;
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (SANDBOX_READ_OFF(data) && SANDBOX_WRITE_OFF(data))
		return 0;

	if (!pink_read_argument(tid, abi, data->regs, 1, &flags)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 1) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	wr = open_wr_check(flags, &create, &resolv);

	memset(&info, 0, sizeof(sys_info_t));
	info.create = create;
	info.resolv = resolv;

	r = 0;
	if (wr && !SANDBOX_WRITE_OFF(data)) {
		info.whitelisting = SANDBOX_WRITE_DENY(data);
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !SANDBOX_READ_OFF(data)) {
		info.whitelisting = SANDBOX_READ_DENY(data);
		info.wblist = SANDBOX_READ_DENY(data) ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	return r;
}

int sys_openat(pink_easy_process_t *current, const char *name)
{
	int r;
	bool resolv, wr;
	enum create_mode create;
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (SANDBOX_READ_OFF(data) && SANDBOX_WRITE_OFF(data))
		return 0;

	/* Check mode argument first */
	if (!pink_read_argument(tid, abi, data->regs, 2, &flags)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 2) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	wr = open_wr_check(flags, &create, &resolv);

	memset(&info, 0, sizeof(sys_info_t));
	info.at = true;
	info.index = 1;
	info.create = create;
	info.resolv = resolv;

	r = 0;
	if (wr && !SANDBOX_WRITE_OFF(data)) {
		info.whitelisting = SANDBOX_WRITE_DENY(data);
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && !SANDBOX_READ_OFF(data)) {
		info.whitelisting = SANDBOX_READ_DENY(data);
		info.wblist = SANDBOX_READ_DENY(data) ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	return r;
}
