/*
 * sydbox/sys-open.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
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

#include "log.h"

static bool open_wr_check(long flags, can_mode_t *can_mode, bool *fail_if_exist)
{
	can_mode_t m;
	bool f;

	assert(can_mode);
	assert(fail_if_exist);

	f = false;
	m = flags & O_CREAT ? CAN_ALL_BUT_LAST : CAN_EXISTING;
	if (flags & O_EXCL) {
		if (m == CAN_EXISTING) {
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
			m |= CAN_NOLINKS;
			f = true;
		}
	}

	*can_mode = m;
	*fail_if_exist = f;

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

int sys_open(struct pink_easy_process *current, const char *name)
{
	int r;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	bool fail_if_exist, wr;
	can_mode_t can_mode;
	long flags;
	sysinfo_t info;

	if (sandbox_read_off(data) && sandbox_write_off(data))
		return 0;

	/* Check flags argument first */
	if (!pink_read_argument(tid, abi, &data->regs, 1, &flags)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %d, 1) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 1) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	wr = open_wr_check(flags, &can_mode, &fail_if_exist);
	log_trace("wr_check:%ld for sys:%s() returned"
		  " wr=%s can_mode=%d fail_if_exist=%s",
		  flags, name,
		  wr ? "true" : "false",
		  can_mode,
		  fail_if_exist ? "true" : "false");

	init_sysinfo(&info);
	info.can_mode = can_mode;
	info.fail_if_exist = fail_if_exist;

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
	bool fail_if_exist, wr;
	can_mode_t can_mode;
	long flags;
	sysinfo_t info;

	if (sandbox_read_off(data) && sandbox_write_off(data))
		return 0;

	/* Check flags argument first */
	if (!pink_read_argument(tid, abi, &data->regs, 2, &flags)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %d, 2) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %d, 2) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	wr = open_wr_check(flags, &can_mode, &fail_if_exist);
	log_trace("wr_check:%ld for sys:%s() returned"
		  " wr=%s can_mode=%d fail_if_exist=%s",
		  flags, name,
		  wr ? "true" : "false",
		  can_mode,
		  fail_if_exist ? "true" : "false");

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = can_mode;
	info.fail_if_exist = fail_if_exist;

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
