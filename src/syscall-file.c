/*
 * sydbox/syscall-file.c
 *
 * File system related system call handlers
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h> /* TODO: check in configure.ac */
#include <errno.h>
#include <fcntl.h>
#include <pinktrace/pink.h>
#include "strtable.h"
#include "canonicalize.h"
#include "log.h"

struct open_info {
	bool may_read;
	bool may_write;
	can_mode_t can_mode;
	enum syd_stat syd_mode;
};

static bool check_access_mode(syd_proc_t *current, int mode)
{
	bool r;

	assert(current);

	if (mode & R_OK && !sandbox_read_off(current))
		r = true;
	else if (mode & W_OK && !sandbox_write_off(current))
		r = true;
	else if (mode & X_OK && !sandbox_exec_off(current))
		r = true;
	else
		r = false;

	log_trace("check_mode(0x%x) = %d|%s|", mode, r, strbool(r));
	return r;
}

static int check_access(syd_proc_t *current, sysinfo_t *info, int mode)
{
	int r;

	r = 0;
	if (!sandbox_write_off(current) && mode & W_OK)
		r = box_check_path(current, info);

	if (!r && !sysdeny(current) && !sandbox_read_off(current) && mode & R_OK) {
		info->access_mode = sandbox_read_deny(current)
				    ? ACCESS_WHITELIST
				    : ACCESS_BLACKLIST;
		info->access_list = sandbox_read_deny(current)
				    ? &current->config.whitelist_read
				    : &current->config.blacklist_read;
		info->access_filter = &sydbox->config.filter_read;
		r = box_check_path(current, info);
	}

	if (!r && !sysdeny(current) && !sandbox_exec_off(current) && mode & X_OK) {
		info->access_mode = sandbox_exec_deny(current)
				    ? ACCESS_WHITELIST
				    : ACCESS_BLACKLIST;
		info->access_list = sandbox_exec_deny(current)
				    ? &current->config.whitelist_exec
				    : &current->config.blacklist_exec;
		info->access_filter = &sydbox->config.filter_exec;
		r = box_check_path(current, info);
	}

	return r;
}

int sys_access(syd_proc_t *current)
{
	int r;
	long mode;
	sysinfo_t info;

	if (sandbox_file_off(current))
		return 0;

	if ((r = syd_read_argument(current, 1, &mode)) < 0)
		return r;
	if (!check_access_mode(current, mode))
		return 0;

	init_sysinfo(&info);
	info.safe = true;
	info.deny_errno = EACCES;

	return check_access(current, &info, mode);
}

int sys_faccessat(syd_proc_t *current)
{
	int r;
	long mode, flags;
	sysinfo_t info;

	if (sandbox_file_off(current))
		return 0;

	/* check mode and then the AT_SYMLINK_NOFOLLOW flag */
	if ((r = syd_read_argument(current, 2, &mode)) < 0)
		return r;
	if (!check_access_mode(current, mode))
		return 0;
	if ((r = syd_read_argument(current, 3, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.safe = true;
	info.deny_errno = EACCES;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	return check_access(current, &info, mode);
}

/* TODO: Do we need to care about O_PATH? */
static void init_open_info(syd_proc_t *current, int flags, struct open_info *info)
{
	assert(current);
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

	log_trace("check_flags(0x%x) = read:%s write:%s can_mode:0x%x syd_mode:0x%x",
		  flags, strbool(info->may_read), strbool(info->may_write),
		  info->can_mode, info->syd_mode);
}

static int check_open(syd_proc_t *current, sysinfo_t *info, bool may_write)
{
	int r = 0;

	if (may_write && !sandbox_write_off(current))
		r = box_check_path(current, info);

	if (!r && !sysdeny(current) && !sandbox_read_off(current)) {
		info->access_mode = sandbox_read_deny(current)
				    ? ACCESS_WHITELIST
				    : ACCESS_BLACKLIST;
		info->access_list = sandbox_read_deny(current)
				    ? &current->config.whitelist_read
				    : &current->config.blacklist_read;
		info->access_filter = &sydbox->config.filter_read;
		r = box_check_path(current, info);
	}

	return r;
}

int sys_open(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;
	struct open_info open_info;

	if (sandbox_read_off(current) && sandbox_write_off(current))
		return 0;

	/* check flags first */
	if ((r = syd_read_argument(current, 1, &flags)) < 0)
		return r;

	init_open_info(current, flags, &open_info);
	init_sysinfo(&info);
	info.can_mode = open_info.can_mode;
	info.syd_mode = open_info.syd_mode;

	return check_open(current, &info, open_info.may_write);
}

int sys_openat(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;
	struct open_info open_info;

	if (sandbox_read_off(current) && sandbox_write_off(current))
		return 0;

	/* check flags first */
	if ((r = syd_read_argument(current, 2, &flags)) < 0)
		return r;

	init_open_info(current, flags, &open_info);
	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = open_info.can_mode;
	info.syd_mode = open_info.syd_mode;

	return check_open(current, &info, open_info.may_write);
}

int sys_chmod(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_fchmodat(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	/* check for AT_SYMLINK_NOFOLLOW */
	if ((r = syd_read_argument(current, 3, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, &info);
}

int sys_chown(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_lchown(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, &info);
}

int sys_fchownat(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	/* check for AT_SYMLINK_NOFOLLOW */
	if ((r = syd_read_argument(current, 4, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, &info);
}

int sys_creat(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode = CAN_ALL_BUT_LAST;

	return box_check_path(current, &info);
}

int sys_close(syd_proc_t *current)
{
	int r;
	long fd;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	if ((r = syd_read_argument(current, 0, &fd)) < 0)
		return r;
	if (hashtable_find(current->sockmap, fd + 1, 0))
		current->args[0] = fd;
	return 0;
}

int sysx_close(syd_proc_t *current)
{
	int r;
	long retval;
	ht_int64_node_t *node;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    !current->args[0])
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval == -1) {
		log_trace("ignoring failed close");
		return 0;
	}

	node = hashtable_find(current->sockmap, current->args[0] + 1, 0);
	assert(node);

	node->key = 0;
	free_sockinfo(node->data);
	node->data = NULL;
	log_trace("closed fd: %ld", current->args[0]);
	return 0;
}

int sys_mkdir(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode = CAN_ALL_BUT_LAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_mkdirat(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_mknod(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode = CAN_ALL_BUT_LAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_mknodat(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_rmdir(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode |= CAN_NOLINKS;
	info.syd_mode |= SYD_STAT_EMPTYDIR;

	return box_check_path(current, &info);
}

int sys_truncate(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_mount(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;

	return box_check_path(current, &info);
}

int sys_umount(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_umount2(syd_proc_t *current)
{
	int r;
#ifdef UMOUNT_NOFOLLOW
	long flags;
#endif
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
#ifdef UMOUNT_NOFOLLOW
	/* check for UMOUNT_NOFOLLOW */
	if ((r = syd_read_argument(current, 1, &flags)) < 0)
		return r;
	if (flags & UMOUNT_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;
#endif

	return box_check_path(current, &info);
}

int sys_utime(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_utimes(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_utimensat(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	/* check for AT_SYMLINK_NOFOLLOW */
	if ((r = syd_read_argument(current, 3, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.null_ok = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, &info);
}

int sys_futimesat(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.null_ok = true;
	info.arg_index = 1;

	return box_check_path(current, &info);
}

int sys_unlink(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode |= CAN_NOLINKS;
	info.syd_mode |= SYD_STAT_NOTDIR;

	return box_check_path(current, &info);
}

int sys_unlinkat(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	if ((r = syd_read_argument(current, 2, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;

	/* If AT_REMOVEDIR flag is set in the third argument, unlinkat()
	 * behaves like rmdir(2), otherwise it behaves like unlink(2).
	 */
	if (flags & AT_REMOVEDIR) { /* rmdir */
		info.can_mode |= CAN_NOLINKS;
		info.syd_mode |= SYD_STAT_EMPTYDIR;
	} else { /* unlink */
		info.can_mode |= CAN_NOLINKS;
		info.syd_mode |= SYD_STAT_NOTDIR;
	}

	return box_check_path(current, &info);
}

int sys_link(syd_proc_t *current)
{
	int r;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	/*
	 * POSIX.1-2001 says that link() should dereference oldpath if it is a
	 * symbolic link. However, since kernel 2.0, Linux does not do
	 * so: if  oldpath is a symbolic link, then newpath is created as a
	 * (hard) link to the same symbolic link file (i.e., newpath becomes a
	 * symbolic link to the same file that oldpath refers to). Some other
	 * implementations behave in the same manner as Linux.
	 * POSIX.1-2008 changes the specification of link(), making it
	 * implementation-dependent whether or not oldpath is dereferenced if
	 * it is a symbolic link.
	 */
	info.can_mode |= CAN_NOLINKS;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
		info.arg_index = 1;
		info.can_mode = CAN_ALL_BUT_LAST;
		info.syd_mode = SYD_STAT_NOEXIST;
		return box_check_path(current, &info);
	}

	return r;
}

int sys_linkat(syd_proc_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	/* check for AT_SYMLINK_FOLLOW */
	if ((r = syd_read_argument(current, 4, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (!(flags & AT_SYMLINK_FOLLOW))
		info.can_mode |= CAN_NOLINKS;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
		info.arg_index = 3;
		info.can_mode &= ~CAN_MODE_MASK;
		info.can_mode |= CAN_ALL_BUT_LAST;
		info.syd_mode = SYD_STAT_NOEXIST;
		return box_check_path(current, &info);
	}

	return r;
}

int sys_rename(syd_proc_t *current)
{
	int r;
	mode_t mode;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode = CAN_NOLINKS;
	info.ret_mode = &mode;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
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
		return box_check_path(current, &info);
	}

	return r;
}

int sys_renameat(syd_proc_t *current)
{
	int r;
	mode_t mode;
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.can_mode = CAN_NOLINKS;
	info.ret_mode = &mode;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
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
		return box_check_path(current, &info);
	}

	return r;
}

int sys_symlink(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST | CAN_NOLINKS;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_symlinkat(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 2;
	info.can_mode = CAN_ALL_BUT_LAST | CAN_NOLINKS;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_setxattr(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_lsetxattr(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, &info);
}

int sys_removexattr(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_lremovexattr(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_write_off(current))
		return 0;

	init_sysinfo(&info);
	info.can_mode |= CAN_NOLINKS;

	return box_check_path(current, &info);
}
