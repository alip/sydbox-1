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

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"
#include "util.h"

int sysx_chdir(struct pink_easy_process *current, PINK_GCC_ATTR((unused)) const char *name)
{
	int r;
	long retval;
	char *cwd;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!pink_read_retval(tid, abi, &data->regs, &retval, NULL)) {
		if (errno != ESRCH) {
			warning("pink_read_retval(%lu, %d) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		/* Unsuccessful chdir(), ignore */
		return 0;
	}

	if ((r = proc_cwd(tid, &cwd)) < 0) {
		warning("proc_cwd(%lu): %d(%s)",
				(unsigned long)tid,
				-r, strerror(-r));
		return panic(current);
	}

	if (!streq(data->cwd, cwd))
		info("process:%lu [abi:%d name:\"%s\" cwd:\"%s\"]"
				" changed directory to \"%s\"",
				(unsigned long)tid, abi,
				data->comm, data->cwd, cwd);

	free(data->cwd);
	data->cwd = cwd;
	return 0;
}
