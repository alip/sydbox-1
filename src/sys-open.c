/*
 * sydbox/sys-open.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

struct open_info {
	bool may_read;
	bool may_write;
	can_mode_t can_mode;
	enum syd_stat syd_mode;
};

/* TODO: Do we need to care about O_PATH? */
static bool open_wr_check(const char *name, long flags, struct open_info *info)
{
	assert(info);

	info->can_mode = flags & O_CREAT ? CAN_ALL_BUT_LAST : CAN_EXISTING;
	info->syd_mode = 0;
	if (flags & O_EXCL) {
		if (info->can_mode == CAN_EXISTING) {
			/* Quoting open(2):
			 * In general, the behavior of O_EXCL is undefined if
			 * it is used without O_CREAT.  There is one exception:
			 * on Linux 2.6 and later, O_EXCL can be used without
			 * O_CREAT if pathname refers to a block device. If
			 * the block device is in use by the system (e.g.,
			 * mounted), open() fails.
			 */
			/* void */;
		} else {
			/* Two things to mention here:
			 * - If O_EXCL is specified in conjunction with
			 *   O_CREAT, and pathname already exists, then open()
			 *   will fail.
			 * - When both O_CREAT and O_EXCL are specified,
			 *   symbolic links are not followed.
			 */
			info->can_mode |= CAN_NOLINKS;
			info->syd_mode |= SYD_STAT_NOEXIST;
		}
	}

	if (flags & O_DIRECTORY)
		info->syd_mode |= SYD_STAT_ISDIR;
	if (flags & O_NOFOLLOW)
		info->syd_mode |= SYD_STAT_NOFOLLOW;

	/* `unsafe' flag combinations:
	 * - O_RDONLY | O_CREAT
	 * - O_WRONLY
	 * - O_RDWR
	 */
	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		info->may_read = true;
		if (flags & O_CREAT) {
			/* file creation is `write' */
			info->may_write = true;
		} else {
			info->may_write = false;
		}
		break;
	case O_WRONLY:
		info->may_read = false;
		info->may_write = true;
		break;
	case O_RDWR:
		info->may_read = info->may_write = true;
		break;
	default:
		info->may_read = info->may_write = false;
	}

	log_trace("wr_check:%ld for sys:%s() returned"
		  " may_write=%s can_mode=%d syd_mode=%#x",
		  flags, name,
		  info->may_write ? "true" : "false",
		  info->can_mode,
		  info->syd_mode);

	return info->may_write;
}

int sys_open(struct pink_easy_process *current, const char *name)
{
	int r;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	bool wr;
	long flags;
	sysinfo_t info;
	struct open_info open_info;

	if (sandbox_read_off(data) && sandbox_write_off(data))
		return 0;

	/* Check flags argument first */
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

	wr = open_wr_check(name, flags, &open_info);
	init_sysinfo(&info);
	info.can_mode = open_info.can_mode;
	info.syd_mode = open_info.syd_mode;

	r = 0;
	if (wr && !sandbox_write_off(data))
		r = box_check_path(current, name, &info);

	if (!r && !data->deny && !sandbox_read_off(data)) {
		info.access_mode = sandbox_read_deny(data)
				   ? ACCESS_WHITELIST
				   : ACCESS_BLACKLIST;
		info.access_list = sandbox_read_deny(data)
				   ? &data->config.whitelist_read
				   : &data->config.blacklist_read;
		info.access_filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	return r;
}

int sys_openat(struct pink_easy_process *current, const char *name)
{
	int r;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	bool wr;
	long flags;
	sysinfo_t info;
	struct open_info open_info;

	if (sandbox_read_off(data) && sandbox_write_off(data))
		return 0;

	/* Check flags argument first */
	if ((r = pink_read_argument(tid, abi, &data->regs, 2, &flags)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_argument(%lu, %d, 2) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -r, strerror(-r));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 2) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -r, strerror(-r));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	wr = open_wr_check(name, flags, &open_info);
	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = open_info.can_mode;
	info.syd_mode = open_info.syd_mode;

	r = 0;
	if (wr && !sandbox_write_off(data))
		r = box_check_path(current, name, &info);

	if (!r && !data->deny && !sandbox_read_off(data)) {
		info.access_mode = sandbox_read_deny(data)
				   ? ACCESS_WHITELIST
				   : ACCESS_BLACKLIST;
		info.access_list = sandbox_read_deny(data)
				   ? &data->config.whitelist_read
				   : &data->config.blacklist_read;
		info.access_filter = &sydbox->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	return r;
}
