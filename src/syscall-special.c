/*
 * sydbox/syscall-special.c
 *
 * Special system call handlers
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <pinktrace/pink.h>
#include "pathdecode.h"
#include "proc.h"
#include "bsd-compat.h"
#include "log.h"
#include "sockmap.h"

#include <fcntl.h>
#include <sys/stat.h>
#if PINK_ARCH_X86_64
# define __i386__
# define stat kernel_stat
# define stat64 kernel_stat64
# define __old_kernel_stat stat32
/* These might be macros. */
# undef st_atime
# undef st_mtime
# undef st_ctime
# include <asm/stat.h>
# undef __i386__
#elif PINK_ABIS_SUPPORTED > 1
# warning do not know the size of stat buffer for non-default ABIs
#endif

int sysx_chdir(syd_proc_t *current)
{
	int r;
	long retval;
	char *cwd;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		log_trace("ignoring failed system call");
		return 0;
	}

	if ((r = proc_cwd(current->pid, sydbox->config.use_toolong_hack, &cwd)) < 0) {
		err_warning(-r, "proc_cwd failed");
		return panic(current);
	}

	if (!streq(current->cwd, cwd))
		log_check("dir change old=`%s' new=`%s'", current->cwd, cwd);

	free(current->cwd);
	current->cwd = cwd;
	return 0;
}

int sys_fork(syd_proc_t *current)
{
	sydbox->pidwait = current->pid;
	log_trace("waitpid set to pid:%u", sydbox->pidwait);
	return 0;
}

int sys_execve(syd_proc_t *current)
{
	int r;
	char *path = NULL, *abspath = NULL;

	r = path_decode(current, 0, &path);
	if (r == -ESRCH)
		return r;
	else if (r < 0)
		return deny(current, errno);

	r = box_resolve_path(path, current->cwd, current->pid, RPATH_EXIST, &abspath);
	if (r < 0) {
		err_access(-r, "resolve_path(`%s')", path);
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(`%s')", current->sysname, path);
		free(path);
		return r;
	}
	free(path);

	/*
	 * Handling exec.kill_if_match and exec.resume_if_match:
	 *
	 * Resolve and save the path argument in current->abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	current->abspath = abspath;

	switch (current->config.sandbox_exec) {
	case SANDBOX_OFF:
		return 0;
	case SANDBOX_DENY:
		if (box_match_path(&current->config.whitelist_exec, abspath, NULL))
			return 0;
		break;
	case SANDBOX_ALLOW:
		if (!box_match_path(&current->config.blacklist_exec, abspath, NULL))
			return 0;
		break;
	default:
		assert_not_reached();
	}

	r = deny(current, EACCES);

	if (!box_match_path(&sydbox->config.filter_exec, abspath, NULL))
		violation(current, "%s(`%s')", current->sysname, abspath);

	free(abspath);
	current->abspath = NULL;

	return r;
}

int sys_stat(syd_proc_t *current)
{
	int r;
	long addr;
	char path[SYDBOX_PATH_MAX];

	if (current->config.magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	if ((r = syd_read_argument(current, 0, &addr)) < 0)
		return r;
	if (syd_read_string(current, addr, path, SYDBOX_PATH_MAX) < 0)
		return errno == EFAULT ? 0 : -errno;

	r = magic_cast_string(current, path, 1);
	if (r == MAGIC_RET_NOOP) {
		/* no magic */
		return 0;
	} else if (MAGIC_ERROR(r)) {
		log_warning("failed to cast magic=`%s': %s", path, magic_strerror(r));
		if (r == MAGIC_RET_PROCESS_TERMINATED) {
			r = -ESRCH;
		} else {
			switch (r) {
			case MAGIC_RET_NOT_SUPPORTED:
				errno = ENOTSUP;
				break;
			case MAGIC_RET_INVALID_KEY:
			case MAGIC_RET_INVALID_TYPE:
			case MAGIC_RET_INVALID_VALUE:
			case MAGIC_RET_INVALID_QUERY:
			case MAGIC_RET_INVALID_COMMAND:
			case MAGIC_RET_INVALID_OPERATION:
				errno = EINVAL;
				break;
			case MAGIC_RET_OOM:
				errno = ENOMEM;
				break;
			case MAGIC_RET_NOPERM:
			default:
				errno = EPERM;
				break;
			}
			r = deny(current, errno);
		}
	} else if (r != MAGIC_RET_NOOP) {
		/* Write stat buffer */
		const char *bufaddr = NULL;
		size_t bufsize;
		struct stat buf;
#define FAKE_MODE (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define FAKE_RDEV 259 /* /dev/null */
#define FAKE_ATIME 505958400
#define FAKE_MTIME -842745600
#define FAKE_CTIME 558748800
#if PINK_ARCH_X86_64
		struct stat32 buf32;

		if (current->abi == PINK_ABI_I386) {
			memset(&buf32, 0, sizeof(struct stat32));
			buf32.st_mode = FAKE_MODE;
			buf32.st_rdev = FAKE_RDEV;
			buf32.st_atime = FAKE_ATIME;
			buf32.st_mtime = FAKE_MTIME;
			buf32.st_ctime = FAKE_CTIME;
			bufaddr = (char *)&buf32;
			bufsize = sizeof(struct stat32);
		}
#else
		if (current->abi != PINK_ABI_DEFAULT) {
			log_warning("don't know the size of stat buffer for ABI %d", current->abi);
			log_warning("skipped stat() buffer write");
			goto skip_write;
		}
#endif
		if (!bufaddr) {
			memset(&buf, 0, sizeof(struct stat));
			buf.st_mode = FAKE_MODE;
			buf.st_rdev = FAKE_RDEV;
			buf.st_atime = FAKE_ATIME;
			buf.st_mtime = FAKE_MTIME;
			buf.st_ctime = FAKE_CTIME;
			bufaddr = (char *)&buf;
			bufsize = sizeof(struct stat);
		}

		if (pink_read_argument(current->pid, current->regset, 1, &addr) == 0)
			pink_write_vm_data(current->pid, current->regset, addr, bufaddr, bufsize);
#if !PINK_ARCH_X86_64
skip_write:
#endif
		log_magic("accepted magic=`%s'", path);
		if (r < 0)
			errno = -r;
		else if (r == MAGIC_RET_FALSE)
			errno = ENOENT;
		else
			errno = 0;
		r = deny(current, errno);
	}

	/* r is one of:
	 * - return value of deny()
	 * - -ESRCH
	 */
	return r;
}

int sys_dup(syd_proc_t *current)
{
	int r;
	long fd;

	current->args[0] = -1;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	if ((r = syd_read_argument(current, 0, &fd)) < 0)
		return r;

	current->args[0] = fd;
	current->flags |= SYD_STOP_AT_SYSEXIT;
	return 0;
}

int sysx_dup(syd_proc_t *current)
{
	int r;
	long retval;
	const struct sockinfo *oldinfo;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    current->args[0] < 0)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		log_trace("ignoring failed system call");
		return 0;
	}

	if (!(oldinfo = sockmap_find(&current->sockmap, current->args[0]))) {
		log_check("duplicated unknown fd:%ld to fd:%ld", current->args[0], retval);
		return 0;
	}

	sockmap_add(&current->sockmap, retval, sockinfo_xdup(oldinfo));
	log_check("duplicated fd:%ld to fd:%ld", current->args[0], retval);
	return 0;
}

int sys_fcntl(syd_proc_t *current)
{
	bool strict;
	int r, fd, cmd, arg0;

	current->args[0] = -1;
	strict = !sydbox->config.use_seccomp &&
		 sydbox->config.restrict_file_control;

	if (!strict && (sandbox_network_off(current) ||
			!sydbox->config.whitelist_successful_bind))
		return 0;

	if ((r = syd_read_argument_int(current, 1, &cmd)) < 0)
		return r;

	switch (cmd) {
	case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
#endif /* F_DUPFD_CLOEXEC */
		break;
	case F_SETFL:
		if (!strict)
			return 0;
		if ((r = syd_read_argument_int(current, 0, &arg0)) < 0)
			return r;
		if (arg0 & (O_ASYNC|O_DIRECT))
			return deny(current, EINVAL);
		/* fall through */
	case F_GETFL:
	case F_SETOWN:
	case F_SETLK:
	case F_SETLKW:
#if F_SETLK != F_SETLK64
	case F_SETLK64:
#endif
#if F_SETLKW != F_SETLKW
	case F_SETLKW64:
#endif
	case F_GETFD:
	case F_SETFD:
		return 0;
	default:
		if (strict)
			return deny(current, EINVAL);
		return 0;
	}

	if (sandbox_network_off(current) ||
	     !sydbox->config.whitelist_successful_bind)
	    return 0;

	if ((r = syd_read_argument_int(current, 0, &fd)) < 0)
		return r;

	current->args[0] = fd;
	current->args[1] = cmd;
	current->flags |= SYD_STOP_AT_SYSEXIT;
	return 0;
}

int sysx_fcntl(syd_proc_t *current)
{
	int r;
	long retval;
	const struct sockinfo *oldinfo;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    current->args[0] < 0)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		log_trace("ignore failed system call");
		return 0;
	}

	if (!(oldinfo = sockmap_find(&current->sockmap, current->args[0]))) {
		log_check("duplicated unknown fd:%ld to fd:%ld", current->args[0], retval);
		return 0;
	}

	sockmap_add(&current->sockmap, retval, sockinfo_xdup(oldinfo));
	log_check("duplicated fd:%ld to fd:%ld", current->args[0], retval);
	return 0;
}
