/*
 * sydbox/pathdecode.c
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */


#include "sydbox-defs.h"

#include "pathdecode.h"

#include <errno.h>
#include <fcntl.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"
#include "proc.h"

/* Decode the path at the given index and place it in buf.
 * Handles panic()
 * Returns:
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 * >0     : PINK_EASY_CFLAG* flags
 */
int path_decode(struct pink_easy_process *current, unsigned arg_index,
		char **buf)
{
	long addr;
	char path[SYDBOX_PATH_MAX];
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	assert(current);
	assert(buf);

	if (!pink_read_argument(tid, abi, &data->regs, arg_index, &addr))
		goto fail;
	if (pink_read_string(tid, abi, addr, path, SYDBOX_PATH_MAX) < 0)
		goto fail;
	path[SYDBOX_PATH_MAX-1] = '\0';
	*buf = xstrdup(path);
	return 0;
fail:
	if (errno == EFAULT) {
		log_trace("read_string(%lu, %d, %u) returned EFAULT",
			  (unsigned long)tid, abi, arg_index);
		*buf = NULL;
		return -EFAULT;
	}
	if (errno != ESRCH) {
		log_warning("read_string(%lu, %d, %u) failed (errno:%d %s)",
			    (unsigned long)tid, abi, arg_index,
			    errno, strerror(errno));
		return panic(current);
	}
	log_trace("read_string(%lu, %d, %u) failed (errno:%d %s)",
		  (unsigned long)tid, abi, arg_index,
		  errno, strerror(errno));
	log_trace("drop process %s[%lu:%u]",
		  data->comm,
		  (unsigned long)tid, abi);
	return PINK_EASY_CFLAG_DROP;
}

/*
 * Resolve the prefix of an at-suffixed function.
 * Handles panic()
 * Returns:
 * -errno : Negated errno indicating error code
 *  0     : Successful run
 * >0     : PINK_EASY_CFLAG* flags
 */
int path_prefix(struct pink_easy_process *current, unsigned arg_index,
		char **buf)
{
	int r;
	long fd;
	char *prefix = NULL;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	log_check("%s[%lu:%u] arg_index:%u", data->comm,
		  (unsigned long)tid, abi, arg_index);

	if (!pink_read_argument(tid, abi, &data->regs, arg_index, &fd)) {
		if (errno != ESRCH) {
			log_warning("read_argument(%lu, %u, %u) failed (errno:%d %s)",
				    (unsigned long)tid, abi, arg_index,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_argument(%lu, %u, %u) failed (errno:%d %s)",
			  (unsigned long)tid, abi, arg_index,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]",
			  data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	r = 0;
	if (fd == AT_FDCWD) {
		*buf = NULL;
	} else if (fd < 0) {
		log_check("invalid fd=%ld, skip /proc read", fd);
		*buf = NULL;
		r = -EBADF;
	} else {
		r = proc_fd(tid, fd, &prefix);
		if (r < 0) {
			log_warning("readlink /proc/%lu/fd/%ld failed (errno:%d %s)",
				    (unsigned long)tid, fd,
				    -r, strerror(-r));
			if (r == -ENOENT)
				r = -EBADF; /* correct errno */
		} else {
			*buf = prefix;
		}
	}

	if (r == 0)
		log_check("fd=%ld maps to prefix=`%s'", fd,
			  fd == AT_FDCWD ? "AT_FDCWD" : prefix);

	return 0;
}
