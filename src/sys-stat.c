/*
 * sydbox/sys-stat.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_stat(struct pink_easy_process *current, const char *name)
{
	int r;
	long addr;
	char path[SYDBOX_PATH_MAX];
	struct stat buf;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	if (!pink_read_argument(tid, abi, &data->regs, 0, &addr)
	    || pink_read_string(tid, abi, addr, path, SYDBOX_PATH_MAX) < 0) {
		/* Don't bother denying the system call here.
		 * Because this should not be a fatal error.
		 */
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DROP : 0;
	}
	path[SYDBOX_PATH_MAX-1] = '\0';

	r = magic_cast_string(current, path, 1);
	if (r == MAGIC_RET_NOOP) {
		/* no magic */
		return 0;
	} else if (MAGIC_ERROR(r)) {
		log_warning("failed to cast magic=`%s': %s", path,
			    magic_strerror(r));
		if (r == MAGIC_RET_PROCESS_TERMINATED) {
			r = PINK_EASY_CFLAG_DROP;
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

		if (pink_read_argument(tid, abi, &data->regs, 1, &addr))
			pink_write_vm_data(tid, abi, addr,
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
	 * - PINK_EASY_CFLAG_DROP
	 */
	return r;
}
