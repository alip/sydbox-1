/*
 * sydbox/syscall-file.c
 *
 * File system related system call handlers
 *
 * Copyright (c) 2011, 2012, 2013, 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
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
#include "pink.h"
#include "bsd-compat.h"
#include "log.h"
#include "sockmap.h"

struct open_info {
	bool may_read;
	bool may_write;
	short rmode;
	enum syd_stat syd_mode;
};

static inline void sysinfo_read_access(syd_process_t *current, sysinfo_t *info)
{
	info->access_mode = sandbox_deny_read(current)
			    ? ACCESS_WHITELIST
			    : ACCESS_BLACKLIST;
	info->access_list = &P_BOX(current)->acl_read;
	info->access_filter = &sydbox->config.filter_read;
}

static bool check_access_mode(syd_process_t *current, int mode)
{
	bool r;

	assert(current);

	if (mode & W_OK && !sandbox_off_write(current))
		r = true;
	else if (!sandbox_off_read(current))
		r = true;
	else
		r = false;

	return r;
}

static int check_access(syd_process_t *current, sysinfo_t *info, int mode)
{
	int r = 0;
	bool rd, wr;
	char *abspath = NULL;
	struct stat statbuf;

	rd = !sandbox_off_read(current); /* every mode `check' is a read access */
	wr = !sandbox_off_write(current) && mode & W_OK;

	if (wr && rd) {
		info->ret_abspath = &abspath;
		info->ret_statbuf = &statbuf;
	}
	if (wr) {
		r = box_check_path(current, info);
		if (r || sysdeny(current))
			goto out;
	}
	if (rd) {
		if (info->ret_abspath) {
			info->cache_abspath = abspath;
			info->ret_abspath = NULL;
		}
		if (info->ret_statbuf) {
			info->cache_statbuf = info->ret_statbuf;
			info->ret_statbuf = NULL;
		}
		sysinfo_read_access(current, info);
		r = box_check_path(current, info);
	}

out:
	if (abspath)
		free(abspath);
	return r;
}


int sys_access(syd_process_t *current)
{
	int r;
	long mode;
	sysinfo_t info;

	if (sandbox_off_file(current))
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

int sys_faccessat(syd_process_t *current)
{
	int r;
	long mode, flags;
	sysinfo_t info;

	if (sandbox_off_file(current))
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
		info.rmode |= RPATH_NOFOLLOW;

	return check_access(current, &info, mode);
}

/* TODO: Do we need to care about O_PATH? */
static void init_open_info(syd_process_t *current, int flags, struct open_info *info)
{
	assert(current);
	assert(info);

	info->rmode = flags & O_CREAT ? RPATH_NOLAST : RPATH_EXIST;
	info->syd_mode = 0;
	if (flags & O_EXCL) {
		if (info->rmode == RPATH_EXIST) {
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
			info->rmode |= RPATH_NOFOLLOW;
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
}

static int check_open(syd_process_t *current, sysinfo_t *info,
		      const struct open_info *open_info)
{
	int r = 0;
	char *abspath = NULL;
	bool rd, wr;
	struct stat statbuf;

	rd = !sandbox_off_read(current) && open_info->may_read;
	wr = !sandbox_off_write(current) && open_info->may_write;

	if (wr && rd) {
		info->ret_abspath = &abspath;
		info->ret_statbuf = &statbuf;
	}
	if (wr) {
		r = box_check_path(current, info);
		if (r || sysdeny(current))
			goto out;
	}
	if (rd) {
		if (info->ret_abspath) {
			info->cache_abspath = *info->ret_abspath;
			info->ret_abspath = NULL;
		}
		if (info->ret_statbuf) {
			info->cache_statbuf = info->ret_statbuf;
			info->ret_statbuf = NULL;
		}
		sysinfo_read_access(current, info);
		r = box_check_path(current, info);
	}

out:
	if (abspath)
		free(abspath);
	return r;
}

static int restrict_open_flags(syd_process_t *current, int flags)
{
	if (!sydbox->config.use_seccomp &&
	    sydbox->config.restrict_file_control &&
	    flags & (O_ASYNC|O_DIRECT|O_SYNC))
		return deny(current, EINVAL);
	return 0;
}

int sys_open(syd_process_t *current)
{
	bool strict;
	int r, flags;
	sysinfo_t info;
	struct open_info open_info;

	strict = !sydbox->config.use_seccomp &&
		 sydbox->config.restrict_file_control;

	if (!strict && sandbox_off_read(current) && sandbox_off_write(current))
		return 0;

	/* check flags first */
	if ((r = syd_read_argument_int(current, 1, &flags)) < 0)
		return r;
	if ((r = restrict_open_flags(current, flags)) < 0)
		return r;

	if (sandbox_off_read(current) && sandbox_off_write(current))
		return 0;

	init_open_info(current, flags, &open_info);
	init_sysinfo(&info);
	info.rmode = open_info.rmode;
	info.syd_mode = open_info.syd_mode;

	return check_open(current, &info, &open_info);
}

int sys_openat(syd_process_t *current)
{
	bool strict;
	int r, flags;
	sysinfo_t info;
	struct open_info open_info;

	strict = !sydbox->config.use_seccomp &&
		 sydbox->config.restrict_file_control;

	if (!strict && sandbox_off_read(current) && sandbox_off_write(current))
		return 0;

	/* check flags first */
	if ((r = syd_read_argument_int(current, 2, &flags)) < 0)
		return r;
	if ((r = restrict_open_flags(current, flags)) < 0)
		return r;

	if (sandbox_off_read(current) && sandbox_off_write(current))
		return 0;

	init_open_info(current, flags, &open_info);
	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.rmode = open_info.rmode;
	info.syd_mode = open_info.syd_mode;

	return check_open(current, &info, &open_info);
}

int sys_chmod(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_fchmodat(syd_process_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	/* check for AT_SYMLINK_NOFOLLOW */
	if ((r = syd_read_argument(current, 3, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.rmode |= RPATH_NOFOLLOW;

	return box_check_path(current, &info);
}

int sys_chown(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_lchown(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode |= RPATH_NOFOLLOW;

	return box_check_path(current, &info);
}

int sys_fchownat(syd_process_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	/* check for AT_SYMLINK_NOFOLLOW */
	if ((r = syd_read_argument(current, 4, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.rmode |= RPATH_NOFOLLOW;

	return box_check_path(current, &info);
}

int sys_creat(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode = RPATH_NOLAST;

	return box_check_path(current, &info);
}

int sys_close(syd_process_t *current)
{
	int r;
	long fd;

	current->args[0] = -1;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	if ((r = syd_read_argument(current, 0, &fd)) < 0)
		return r;
	if (sockmap_find(&P_SOCKMAP(current), fd))
		current->args[0] = fd;
	return 0;
}

int sysx_close(syd_process_t *current)
{
	int r;
	long retval;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    current->args[0] < 0)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval == -1) {
		/* ignore failed close */
		return 0;
	}

	sockmap_remove(&P_SOCKMAP(current), current->args[0]);
	return 0;
}

int sys_mkdir(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode = RPATH_NOLAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_mkdirat(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.rmode = RPATH_NOLAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_mknod(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode = RPATH_NOLAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_mknodat(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.rmode = RPATH_NOLAST;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_rmdir(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode |= RPATH_NOFOLLOW;
	info.syd_mode |= SYD_STAT_EMPTYDIR;

	return box_check_path(current, &info);
}

int sys_truncate(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_mount(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;

	return box_check_path(current, &info);
}

int sys_umount(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_umount2(syd_process_t *current)
{
#ifdef UMOUNT_NOFOLLOW
	int r;
	long flags;
#endif
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
#ifdef UMOUNT_NOFOLLOW
	/* check for UMOUNT_NOFOLLOW */
	if ((r = syd_read_argument(current, 1, &flags)) < 0)
		return r;
	if (flags & UMOUNT_NOFOLLOW)
		info.rmode |= RPATH_NOFOLLOW;
#endif

	return box_check_path(current, &info);
}

int sys_utime(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_utimes(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_utimensat(syd_process_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	/* check for AT_SYMLINK_NOFOLLOW */
	if ((r = syd_read_argument(current, 3, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.null_ok = true;
	info.arg_index = 1;
	if (flags & AT_SYMLINK_NOFOLLOW)
		info.rmode |= RPATH_NOFOLLOW;

	return box_check_path(current, &info);
}

int sys_futimesat(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.null_ok = true;
	info.arg_index = 1;

	return box_check_path(current, &info);
}

int sys_unlink(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode |= RPATH_NOFOLLOW;
	info.syd_mode |= SYD_STAT_NOTDIR;

	return box_check_path(current, &info);
}

int sys_unlinkat(syd_process_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_off_write(current))
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
		info.rmode |= RPATH_NOFOLLOW;
		info.syd_mode |= SYD_STAT_EMPTYDIR;
	} else { /* unlink */
		info.rmode |= RPATH_NOFOLLOW;
		info.syd_mode |= SYD_STAT_NOTDIR;
	}

	return box_check_path(current, &info);
}

int sys_link(syd_process_t *current)
{
	int r;
	sysinfo_t info;

	if (sandbox_off_write(current))
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
	info.rmode |= RPATH_NOFOLLOW;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
		info.arg_index = 1;
		info.rmode = RPATH_NOLAST;
		info.syd_mode = SYD_STAT_NOEXIST;
		return box_check_path(current, &info);
	}

	return r;
}

int sys_linkat(syd_process_t *current)
{
	int r;
	long flags;
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	/* check for AT_SYMLINK_FOLLOW */
	if ((r = syd_read_argument(current, 4, &flags)) < 0)
		return r;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	if (!(flags & AT_SYMLINK_FOLLOW))
		info.rmode |= RPATH_NOFOLLOW;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
		info.arg_index = 3;
		info.rmode &= ~RPATH_MASK;
		info.rmode |= RPATH_NOLAST;
		info.syd_mode = SYD_STAT_NOEXIST;
		return box_check_path(current, &info);
	}

	return r;
}

int sys_rename(syd_process_t *current)
{
	int r;
	struct stat statbuf;
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode = RPATH_NOFOLLOW;
	info.ret_statbuf = &statbuf;

	statbuf.st_mode = 0;
	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
		info.arg_index = 1;
		info.rmode &= ~RPATH_MASK;
		info.rmode |= RPATH_NOLAST;
		if (S_ISDIR(statbuf.st_mode)) {
			/* oldpath specifies a directory.
			 * In this case, newpath must either not exist,
			 * or it must specify an empty directory.
			 */
			info.syd_mode |= SYD_STAT_EMPTYDIR;
		}
		info.ret_statbuf = NULL;
		return box_check_path(current, &info);
	}

	return r;
}

int sys_renameat(syd_process_t *current)
{
	int r;
	struct stat statbuf;
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 1;
	info.rmode = RPATH_NOFOLLOW;
	info.ret_statbuf = &statbuf;

	r = box_check_path(current, &info);
	if (!r && !sysdeny(current)) {
		info.arg_index = 3;
		info.rmode &= ~RPATH_MASK;
		info.rmode |= RPATH_NOLAST;
		if (S_ISDIR(statbuf.st_mode)) {
			/* oldpath specifies a directory.
			 * In this case, newpath must either not exist,
			 * or it must specify an empty directory.
			 */
			info.syd_mode |= SYD_STAT_EMPTYDIR;
		}
		info.ret_statbuf = NULL;
		return box_check_path(current, &info);
	}

	return r;
}

int sys_symlink(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.rmode = RPATH_NOLAST | RPATH_NOFOLLOW;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

int sys_symlinkat(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.at_func = true;
	info.arg_index = 2;
	info.rmode = RPATH_NOLAST | RPATH_NOFOLLOW;
	info.syd_mode = SYD_STAT_NOEXIST;

	return box_check_path(current, &info);
}

static int check_listxattr(syd_process_t *current, bool nofollow)
{
	sysinfo_t info;

	if (sandbox_off_read(current))
		return 0;

	init_sysinfo(&info);
	info.deny_errno = ENOTSUP;
	info.safe = true;
	if (nofollow)
		info.rmode |= RPATH_NOFOLLOW;
	sysinfo_read_access(current, &info);

	return box_check_path(current, &info);
}

int sys_listxattr(syd_process_t *current)
{
	return check_listxattr(current, false);
}

int sys_llistxattr(syd_process_t *current)
{
	return check_listxattr(current, true);
}

int sys_setxattr(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_lsetxattr(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode |= RPATH_NOFOLLOW;

	return box_check_path(current, &info);
}

int sys_removexattr(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);

	return box_check_path(current, &info);
}

int sys_lremovexattr(syd_process_t *current)
{
	sysinfo_t info;

	if (sandbox_off_write(current))
		return 0;

	init_sysinfo(&info);
	info.rmode |= RPATH_NOFOLLOW;

	return box_check_path(current, &info);
}
