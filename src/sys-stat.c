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

#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"

int sys_stat(struct pink_easy_process *current, PINK_GCC_ATTR((unused)) const char *name)
{
	int r;
	long addr;
	char path[SYDBOX_PATH_MAX];
	struct stat buf;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.magic_lock == LOCK_SET) /* No magic allowed! */
		return 0;

	if (!pink_read_argument(tid, abi, &data->regs, 0, &addr)
			|| pink_read_string(tid, abi, addr,
				path, SYDBOX_PATH_MAX) < 0) {
		/* Don't bother denying the system call here.
		 * Because this should not be a fatal error.
		 */
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DROP : 0;
	}
	path[SYDBOX_PATH_MAX-1] = '\0';

	r = magic_cast_string(current, path, 1);
	if (r < 0) {
		log_warning("failed to cast magic=`%s': %s", path, magic_strerror(r));
		switch (r) {
		case MAGIC_ERROR_INVALID_KEY:
		case MAGIC_ERROR_INVALID_TYPE:
		case MAGIC_ERROR_INVALID_VALUE:
		case MAGIC_ERROR_INVALID_QUERY:
			errno = EINVAL;
			break;
		case MAGIC_ERROR_OOM:
			errno = ENOMEM;
			break;
		default:
			errno = 0;
			break;
		}
		r = deny(current, errno);
	}
	else if (r > 0) {
		/* Encode stat buffer */
		memset(&buf, 0, sizeof(struct stat));
		buf.st_mode = S_IFCHR | (S_IRUSR | S_IWUSR) | (S_IRGRP | S_IWGRP) | (S_IROTH | S_IWOTH);
		buf.st_rdev = 259; /* /dev/null */
		/* Fill with random(!) numbers */
		buf.st_atime = 505958400;
		buf.st_mtime = -842745600;
		buf.st_ctime = 558748800;

		if (pink_read_argument(tid, abi, &data->regs, 1, &addr))
			pink_write_vm_data(tid, abi, addr, (const char *)&buf, sizeof(struct stat));
		log_magic("accepted magic=`%s'", path);
		errno = (r == MAGIC_QUERY_FALSE) ? ENOENT : 0;
		r = deny(current, errno);
	}

	return r;
}
