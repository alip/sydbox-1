/*
 * sydbox/sys-chdir.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"
#include "log.h"
#include "util.h"

int sysx_chdir(struct pink_easy_process *current, const char *name)
{
	int r;
	long retval;
	char *cwd;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if ((r = pink_read_retval(tid, abi, &data->regs, &retval, NULL)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_retval(%lu, %d) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -r, strerror(-r));
			return panic(current);
		}
		log_trace("read_retval(%lu, %d) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -r, strerror(-r));
		log_trace("drop process %s[%lu:%u]",
			  data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		/* Unsuccessful chdir(), ignore */
		return 0;
	}

	if ((r = proc_cwd(tid, &cwd)) < 0) {
		log_warning("proc_cwd for process %s[%lu:%u]"
			    " failed (errno:%d %s)",
			    data->comm,
			    (unsigned long)tid, abi,
			    -r, strerror(-r));
		return panic(current);
	}

	if (!streq(data->cwd, cwd))
		log_check("process %s[%lu:%u] changed directory", data->comm,
			  (unsigned long)tid, abi);
		log_check("old cwd=`%s'", data->cwd);
		log_check("new cwd=`%s'", cwd);

	free(data->cwd);
	data->cwd = cwd;
	return 0;
}
