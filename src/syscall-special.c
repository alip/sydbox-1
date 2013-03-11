/*
 * sydbox/syscall-special.c
 *
 * Special system call handlers
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pinktrace/pink.h>
#include "pathdecode.h"
#include "proc.h"
#include "canonicalize.h"
#include "log.h"
#include "sockmap.h"

int sysx_chdir(syd_proc_t *current)
{
	int r;
	long retval;
	pid_t pid = GET_PID(current);
	char *cwd;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		log_trace("ignoring failed system call");
		return 0;
	}

	if ((r = proc_cwd(pid, &cwd)) < 0) {
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
	sydbox->pidwait = GET_PID(current);
	return 0;
}

int sys_execve(syd_proc_t *current)
{
	int r;
	pid_t pid = GET_PID(current);
	char *path = NULL, *abspath = NULL;

	r = path_decode(current, 0, &path);
	if (r == -ESRCH)
		return r;
	else if (r < 0)
		return deny(current, errno);

	r = box_resolve_path(path, current->cwd, pid, CAN_EXISTING, &abspath);
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
	struct stat buf;

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
		/* Encode stat buffer */
		memset(&buf, 0, sizeof(struct stat));
		buf.st_mode = S_IFCHR |
			      (S_IRUSR | S_IWUSR) |
			      (S_IRGRP | S_IWGRP) |
			      (S_IROTH | S_IWOTH);
		buf.st_rdev = 259; /* /dev/null */
		/* Fill with random(!) numbers */
		buf.st_atime = 505958400;
		buf.st_mtime = -842745600;
		buf.st_ctime = 558748800;

		if (pink_read_argument(current->pink, 1, &addr) == 0)
			pink_write_vm_data(current->pink, addr,
					   (const char *)&buf,
					   sizeof(struct stat));
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

	if (!(oldinfo = sockmap_find(current->sockmap, current->args[0]))) {
		log_check("duplicated unknown fd:%ld to fd:%ld", current->args[0], retval);
		return 0;
	}

	sockmap_add(current->sockmap, retval, sockinfo_xdup(oldinfo));
	log_check("duplicated fd:%ld to fd:%ld", current->args[0], retval);
	return 0;
}

int sys_fcntl(syd_proc_t *current)
{
	int r;
	long fd, cmd;

	current->args[0] = -1;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	if ((r = syd_read_argument(current, 1, &cmd)) < 0)
		return r;

	/* We're interested in two commands:
	 * fcntl(fd, F_DUPFD);
	 * fcntl(fd, F_DUPFD_CLOEXEC);
	 */
	switch (cmd) {
	case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
#endif /* F_DUPFD_CLOEXEC */
		current->args[1] = cmd;
		break;
	default:
		return 0;
	}

	if ((r = syd_read_argument(current, 0, &fd)) < 0)
		return r;

	current->args[0] = fd;
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

	if (!(oldinfo = sockmap_find(current->sockmap, current->args[0]))) {
		log_check("duplicated unknown fd:%ld to fd:%ld", current->args[0], retval);
		return 0;
	}

	sockmap_add(current->sockmap, retval, sockinfo_xdup(oldinfo));
	log_check("duplicated fd:%ld to fd:%ld", current->args[0], retval);
	return 0;
}
