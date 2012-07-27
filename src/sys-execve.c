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

#include <errno.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_execve(pink_easy_process_t *current, const char *name)
{
	int r;
	char *path, *abspath;
	pid_t tid;
	pink_abi_t abi;
	proc_data_t *data;

	if (sydbox->skip_initial_exec) {
		/* Do nothing until exec callback sets this variable to false,
		 * which will indicate the initial execve(2) has been
		 * successfull. */
		return 0;
	}

	tid = pink_easy_process_get_tid(current);
	abi = pink_easy_process_get_abi(current);
	data = pink_easy_process_get_userdata(current);
	path = abspath = NULL;

	r = path_decode(current, 0, &path);
	if (r < 0)
		return deny(current);
	else if (r /* > 0 */)
		return r;

	if ((r = box_resolve_path(path, data->cwd, tid, 0, 1, &abspath)) < 0) {
		info("resolving path:\"%s\" [%s() index:0]"
				" failed for process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"] (errno:%d %s)",
				path, name,
				(unsigned long)tid, abi,
				data->comm, data->cwd,
				-r, strerror(-r));
		errno = -r;
		r = deny(current);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(\"%s\")", name, path);
		free(path);
		return r;
	}
	free(path);

	/* Handling exec.kill_if_match and exec.resume_if_match:
	 *
	 * Resolve and save the path argument in data->abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	data->abspath = abspath;

	switch (data->config.sandbox_exec) {
	case SANDBOX_OFF:
		return 0;
	case SANDBOX_DENY:
		if (box_match_path(abspath, &data->config.whitelist_exec, NULL))
			return 0;
		break;
	case SANDBOX_ALLOW:
		if (!box_match_path(abspath, &data->config.blacklist_exec, NULL))
			return 0;
		break;
	default:
		abort();
	}

	errno = EACCES;
	r = deny(current);

	if (!box_match_path(abspath, &sydbox->config.filter_exec, NULL))
		violation(current, "%s(\"%s\")", name, abspath);

	free(abspath);
	data->abspath = NULL;

	return r;
}
